import { atom, read, update } from 'claude-code'
import type { EngineInterface, Register } from 'claude-code'
import type { AuditEntry, PendingPaste, PendingReview, Targets, Watch } from '../types'
import { settle, shown } from './approval'
import { mask, targetLine, timeline } from './audit'
import { CONTEXT, DNS_NAME, REPO } from './names'
import { describeFindings, scanScript, WHY, type Finding } from './script'
import {
  carriesKnown,
  carriesKnownIn,
  finishPaste,
  hasKnown,
  KEYS,
  leakCheck,
  listKeys,
  pastePending,
  readsSecret,
  REDACTED,
  rotate,
  ROTATE,
  scrub,
  SET,
  setFromFile,
  startPaste,
  type ReadOptions,
} from './secrets'
import { calls, isWrite, mentionsInfra, namesTarget, scriptRuns, switchesTarget, type Call } from './shell'
import { prodTargets, readTargets } from './targets'
import { describePlan, summarizePlan, terraformRuns } from './terraform'
import { ghRunProgress, rolloutProgress } from './watch'

// Guards for infra work from Claude Code:
// 1. the ambient targets in a band above the prompt, told to Claude when they
//    change; direct kubectl/helm changes must name their context, and
//    scripts are read before they run for commands that take the ambient one
//    (a command line run by Bash or as a Monitor's script alike);
// 2. terraform apply only from a saved plan the person approved;
// 3. every infra change logged with the targets of the moment (/timeline);
// 4. read-only watches the mod polls itself, waking Claude when one ends;
// 5. Secret values the model never sees (secrets.ts): tools that write them,
//    commands that would print them refused, output carrying them withheld,
//    and a background task's notification carrying one dropped;
// 6. a call the person approved in one of these dialogs runs on that answer,
//    the permission mode not asking again, when the dialog showed the whole
//    command line (approval.ts).

type Engine = EngineInterface
type Where = { cwd: string; home: string }
type Gate = { deny?: string; confirmed?: string }
type Shown = ReturnType<typeof shown>

const PLUGIN = 'infra-guard'
const AUDIT_KEY = 'audit'
const AUDIT_LIMIT = 1000
const TICK_MS = 5000
const FINISHED_SHOWN = 3
// Direct changes to a cluster must say which one; a script is asked about instead.
const CONTEXT_FLAG: Partial<Record<Call['tool'], string>> = {
  kubectl: 'kubectl --context',
  helm: 'helm --kube-context',
  helmfile: 'helmfile --kube-context',
  argocd: 'argocd --argocd-context',
}
// The flag outranks a kubeContext under helmDefaults or an environment, so
// passing the ambient one could move a helmfile that names its own.
const HELMFILE_NOTE = ' If the helmfile sets kubeContext itself, pass that same context.'

const targets = atom({ plugin: 'infra-guard', key: 'targets' } as const, null as Targets | null)
const watches = atom({ plugin: 'infra-guard', key: 'watches' } as const, [] as Watch[])
const pending = atom({ plugin: 'infra-guard', key: 'pending' } as const, null as PendingPaste | null)
// Whether a plugin above this one sends stored rows on past it (README): set
// when a turn starts after tool calls none of whose result rows came by, as
// each is stored before the next turn starts.
const scrubSkipped = atom({ plugin: 'infra-guard', key: 'scrubSkipped' } as const, false as boolean)
let toolCalls = 0
let resultRows = 0
const LEAK_NOTE =
  `${PLUGIN}: another plugin sends stored rows on past this one, so this session's transcript is not scrubbed; ` +
  'offer the person leak_check once the Secret work is done'
// The pane secret_set opens for the person to paste a value into.
const PASTE = 'secret-paste'
// The pane a script run waits in for the person's review, and what it draws.
const REVIEW = 'script-review'
const review = atom({ plugin: 'infra-guard', key: 'review' } as const, null as PendingReview | null)
// Lines of one script the review draws; past them it says how many more.
const REVIEW_LINES = 2000
// A script run as the person reads it in the review: the call, the targets of
// the moment and every script's text. `reviewing` is the one open now;
// `approval` the one they approved, which runs once, unchanged, on Claude's next try.
type Run = { command: string; cwd: string; ambient: string; scripts: [string, string][]; unread: string[] }
let reviewing: Run | null = null
let approval: Run | null = null

// What Claude was last told of the targets: it hears again only on a change.
let announced = ''
const polling = new Set<string>()
// Bash calls the person approved in a dialog here, by tool_use_id, while they run;
// of those, the ones the permission check asked about and this mod allowed.
const approved = new Set<string>()
const overruled = new Set<string>()

async function where($: Engine): Promise<Where> {
  return { cwd: await $.session.cwd(), home: (await $.env.get('HOME')) ?? '' }
}

function short(path: string, home: string): string {
  return home && path.startsWith(home) ? `~${path.slice(home.length)}` : path
}

async function refresh($: Engine): Promise<Targets> {
  const t = await readTargets($)
  await update($, targets, () => t)
  return t
}

async function ask($: Engine, question: string, yes: string): Promise<boolean> {
  try {
    return (await $.ui.ask(question, { header: PLUGIN, options: [yes, 'Cancel'] })) === yes
  } catch {
    return false
  }
}

function list(items: string[]): string {
  return `${items.slice(0, 8).join(', ')}${items.length > 8 ? ', …' : ''}`
}

async function terraformGate($: Engine, command: string, w: Where, line: Shown): Promise<Gate> {
  const confirmed: string[] = []
  for (const run of terraformRuns(command, w.cwd, w.home)) {
    const dir = short(run.dir, w.home)
    if (run.isAll) {
      return {
        deny:
          `${PLUGIN}: refused ${run.tool} ${run.verb} across every module in ${dir}: there is no one plan to show the person. ` +
          `Plan each module with \`${run.tool} plan -out=tfplan\` and apply it from that plan, or let the person run it with \`!\`.`,
      }
    }
    if (run.verb === 'apply' && run.plan === undefined) {
      return {
        deny:
          `${PLUGIN}: refused ${run.tool} apply without a saved plan. Run \`${run.tool} plan -out=tfplan\`, ` +
          `show the person what it changes, then \`${run.tool} apply tfplan\`.`,
      }
    }
    if (run.verb === 'apply' && run.plan !== undefined) {
      const plan = await $.process.run([run.tool, 'show', '-json', run.plan], { cwd: run.dir, timeoutMs: 60_000 })
      if (plan.exitCode !== 0) return { deny: `${PLUGIN}: could not read the plan ${run.plan}: ${plan.stderr.trim().slice(0, 300)}` }
      const s = summarizePlan(JSON.parse(plan.stdout))
      const losses = [...s.replace, ...s.delete]
      const question = [
        `${run.tool} apply ${run.plan} in ${dir}: ${describePlan(s)}.`,
        ...(losses.length > 0 ? [`Destroys: ${list(losses)}`] : []),
        `Command: ${line.text}`,
        'Apply it?',
      ].join('\n')
      if (!(await ask($, question, losses.length > 0 ? `Apply, destroying ${losses.length}` : 'Apply'))) {
        return { deny: `${PLUGIN}: the person did not approve the plan (${describePlan(s)})` }
      }
      confirmed.push(describePlan(s))
      continue
    }
    const state = await $.process.run([run.tool, 'state', 'list'], { cwd: run.dir, timeoutMs: 60_000 })
    const items = state.stdout.split('\n').filter(Boolean)
    const question = [
      `${run.tool} destroy in ${dir} deletes all ${items.length} resources in its state${items.length > 0 ? `: ${list(items)}` : ''}.`,
      `Command: ${line.text}`,
      'Destroy?',
    ].join('\n')
    if (!(await ask($, question, `Destroy ${items.length}`))) return { deny: `${PLUGIN}: the person did not approve ${run.tool} destroy` }
    confirmed.push(`destroy of ${items.length}`)
  }
  return confirmed.length > 0 ? { confirmed: confirmed.join('; ') } : {}
}

// Reads each script the line runs (and those it runs, two levels down), each
// from the directory it runs in.
async function scriptGate($: Engine, command: string, w: Where, prod: RegExp, line: Shown): Promise<Gate> {
  const queue = scriptRuns(command, w.cwd, w.home).map(run => ({ ...run, depth: 0 }))
  const seen = new Set<string>()
  const findings: Finding[] = []
  const unread: string[] = []
  const texts: [string, string][] = []
  // An approval stands for Claude's next script run alone, and only unchanged.
  const approved = approval
  approval = null
  while (queue.length > 0) {
    const { path, cwd, depth } = queue.shift()!
    if (seen.has(path)) continue
    seen.add(path)
    let text: string
    try {
      text = await $.fs.read(path)
    } catch {
      unread.push(path)
      continue
    }
    texts.push([path, text])
    const scan = scanScript(path, text, w.home, cwd)
    findings.push(...scan.findings)
    if (depth < 2) queue.push(...scan.nested.map(run => ({ ...run, depth: depth + 1 })))
  }
  if (findings.length === 0 && unread.length === 0) return {}
  // Read now: the run binds the targets it would take.
  const t = await refresh($)
  const onProd = prodTargets(t, prod)
  const run: Run = { command, cwd: w.cwd, ambient: targetLine(t), scripts: texts, unread }
  if (approved !== null && JSON.stringify(approved) === JSON.stringify(run)) {
    return { confirmed: `${findings.length} ambient command(s) in scripts, run as the person reviewed them` }
  }
  const reviewed = await openReview($, run, findings, onProd, line, w.home)
  if (reviewed !== undefined) return { deny: reviewed }
  const question = [
    `${seen.size} script(s) would run ${findings.length} command(s) that take the ambient target:`,
    ...describeFindings(findings, w.home),
    ...unread.map(p => `could not read ${short(p, w.home)} to check it`),
    `Ambient now: ${targetLine(t)}${onProd.length > 0 ? `  (PRODUCTION: ${onProd.join(', ')})` : ''}`,
    `Command: ${line.text}`,
    'Run it?',
  ].join('\n')
  if (!(await ask($, question, onProd.length > 0 ? 'Run against production' : 'Run it'))) {
    return {
      deny:
        `${PLUGIN}: the person did not run it. ${describeFindings(findings, w.home).join('; ')}. ` +
        'Pass the target explicitly (kubectl --context, helm --kube-context, gcloud --project, aws --profile).',
    }
  }
  return { confirmed: `${findings.length} ambient command(s) in scripts, run as asked` }
}

// Opens the review of a script run, where the person reads every script whole
// and runs or cancels it: a pane, or, where none is placed unasked (a narrow
// terminal), a band row that opens one. Answers the refusal that tells Claude
// to wait, or undefined where nothing can draw it (the dialog asks instead).
async function openReview($: Engine, run: Run, findings: Finding[], onProd: string[], line: Shown, home: string): Promise<string | undefined> {
  if (reviewing !== null) return `${PLUGIN}: another script run is waiting for the person's review; run this one once they have decided`
  const scripts = run.scripts.map(([path, text]) => {
    const lines = scrub(text).replace(/\t/g, '  ').split('\n')
    if (lines.at(-1) === '') lines.pop()
    const flagged = findings.filter(f => f.file === path).map(f => ({ line: f.line, why: WHY[f.why] }))
    return { path: short(path, home), lines: lines.slice(0, REVIEW_LINES), flagged, more: Math.max(lines.length - REVIEW_LINES, 0) }
  })
  const shown: PendingReview = {
    command: line.text,
    cwd: short(run.cwd, home),
    ambient: run.ambient,
    production: onProd,
    scripts,
    unread: run.unread.map(p => short(p, home)),
    inPane: true,
  }
  await update($, review, () => shown)
  reviewing = run
  const opened = await $.ui
    .open({ id: REVIEW, title: `${PLUGIN}: review before it runs`, focus: true, closeOnEscape: true, holdToasts: true })
    .catch(() => undefined)
  if (opened === undefined || (!opened.isPlaced && opened.reason.startsWith('no-surface'))) {
    reviewing = null
    await update($, review, () => null)
    if (opened !== undefined) await $.ui.close({ id: REVIEW })
    return undefined
  }
  if (!opened.isPlaced) {
    // A pane waiting undrawn would pop up later; the band's button opens it now.
    await $.ui.close({ id: REVIEW })
    await update($, review, r => r && { ...r, inPane: false })
  }
  const names = scripts.map(s => s.path).join(', ')
  return (
    `${PLUGIN}: ${names} would run ${findings.length} command(s) that take the ambient target, so the person is reviewing ` +
    `${opened.isPlaced ? 'it in a pane' : 'it from a row above the prompt'} before it runs. A message arrives when they decide: ` +
    'do not run it again, poll or wait for it before then.'
  )
}

// The review pane, opened by the person from the band: placed at any width.
async function showReview($: Engine) {
  const opened = await $.ui.open({ id: REVIEW, title: `${PLUGIN}: review before it runs`, focus: true, closeOnEscape: true, holdToasts: true })
  if (opened.isPlaced) await update($, review, r => r && { ...r, inPane: true })
}

// The person's answer: Run approves that very run once, for Claude to run
// again; Cancel or Esc refuses it. Claude hears either way.
async function endReview($: Engine, approved: boolean, closePane: boolean) {
  const run = reviewing
  if (run === null) return
  reviewing = null
  const shown = await read($, review)
  await update($, review, () => null)
  if (closePane) await $.ui.close({ id: REVIEW })
  if (approved) approval = run
  const names = shown?.scripts.map(s => s.path).join(', ') || 'the script'
  await $.prompt.submit({
    text: approved
      ? `${PLUGIN}: the person reviewed ${names} and approved the run. Run the same command again now, unchanged, from ${shown?.cwd ?? run.cwd}.`
      : `${PLUGIN}: the person reviewed ${names} and did not run it. Pass the target explicitly (kubectl --context, helm --kube-context, ` +
        'gcloud --project, aws --profile), or ask them what to change.',
  })
}

// The review itself: the call and its targets, the two answers, then every
// script whole with its line numbers, each flagged line marked with why.
function reviewBody($: Engine, e: Parameters<Engine['ui']['resolve']>[0], r: PendingReview) {
  const { Box, Text, Button } = $.ui.resolve(e)
  const prod = r.production.length > 0
  const width = String(Math.max(...r.scripts.map(s => s.lines.length), 1)).length
  const rows = r.scripts.flatMap(s => [
    <Text key={`${s.path}:head`}> </Text>,
    <Text key={`${s.path}:name`} bold>{`${s.path}  (${s.lines.length + s.more} lines, ${s.flagged.length} flagged)`}</Text>,
    ...s.lines.flatMap((text, i) => {
      const n = i + 1
      const why = s.flagged.filter(f => f.line === n).map(f => f.why)
      const number = String(n).padStart(width)
      if (why.length === 0) return [<Text key={`${s.path}:${n}`}>{`  ${number}  ${text}`}</Text>]
      return [
        <Text key={`${s.path}:${n}`} color="error" bold>{`▶ ${number}  ${text}`}</Text>,
        <Text key={`${s.path}:${n}:why`} color="warning">{`  ${' '.repeat(width)}  └ ${[...new Set(why)].join('; ')}`}</Text>,
      ]
    }),
    ...(s.more > 0 ? [<Text key={`${s.path}:more`} dimColor>{`  … ${s.more} more lines not shown`}</Text>] : []),
  ])
  return (
    <Box flexDirection="column">
      <Text bold>{`$ ${r.command}`}</Text>
      <Text dimColor>{`in ${r.cwd}`}</Text>
      <Text color={prod ? 'error' : undefined} bold={prod}>
        {`ambient: ${r.ambient}${prod ? `  PRODUCTION: ${r.production.join(', ')}` : ''}`}
      </Text>
      {/* plain: each answer drawn with its key, `r: Run it   c: Cancel`. */}
      <Box flexDirection="row" columnGap={3}>
        <Button key="review-run" label={prod ? 'Run against production' : 'Run it'} hotkey="r" plain onPress={() => endReview($, true, true)} />
        <Button key="review-cancel" label="Cancel" hotkey="c" plain onPress={() => endReview($, false, true)} />
      </Box>
      <Text dimColor>↑↓ scroll · Esc cancels too</Text>
      {r.unread.map(p => (
        <Text key={`unread:${p}`} color="warning">{`could not read ${p}: it runs unseen`}</Text>
      ))}
      {rows}
    </Box>
  )
}

async function record($: Engine, entry: AuditEntry) {
  const kept = ((await $.store.get(AUDIT_KEY)) as AuditEntry[] | undefined) ?? []
  await $.store.set(AUDIT_KEY, [...kept, entry].slice(-AUDIT_LIMIT))
}

async function setWatch($: Engine, id: string, change: Partial<Watch>) {
  await update($, watches, all => all.map(x => (x.id === id && x.state === 'running' ? { ...x, ...change } : x)))
}

async function announce($: Engine, w: Watch, now: number) {
  const text = `watch ${w.id} (${w.label}) ${w.state} after ${Math.round((now - w.startedAt) / 1000)}s: ${w.status}`
  $.ui.toast(text)
  void $.ui.notify(text, { title: PLUGIN })
  await $.prompt.submit({ text: `${PLUGIN}: ${text}` })
}

async function poll($: Engine, w: Watch, now: number) {
  polling.add(w.id)
  try {
    const r = await $.process.run(w.argv, { timeoutMs: 20_000 })
    const p = w.kind === 'rollout' ? rolloutProgress(r) : ghRunProgress(r)
    const state = p.state === 'running' && now > w.deadline ? 'timeout' : p.state
    await setWatch($, w.id, { status: p.status, state, ...(state === 'running' ? {} : { endedAt: now }) })
    if (state !== 'running') await announce($, { ...w, status: p.status, state }, now)
  } catch (error) {
    await setWatch($, w.id, { status: `poll failed: ${error instanceof Error ? error.message : String(error)}` })
  } finally {
    polling.delete(w.id)
  }
}

async function tick($: Engine, withTargets: boolean) {
  if (withTargets) await refresh($)
  const now = await $.clock.now()
  for (const w of await read($, watches)) if (w.state === 'running' && !polling.has(w.id)) void poll($, w, now)
}

function directGate(found: Call[], t: Targets | null, read: ReadOptions): Gate {
  for (const call of found) {
    const why = readsSecret(call, read)
    if (why !== undefined) return { deny: `${PLUGIN}: refused, ${why}. List keys with ${KEYS}; change a value with ${ROTATE} or ${SET}.` }
  }
  for (const call of found) {
    const flag = CONTEXT_FLAG[call.tool]
    if (flag !== undefined && isWrite(call) && !namesTarget(call)) {
      const ambient = call.tool === 'argocd' ? `ambient argocd context: ${t?.argocd ?? 'unset'}` : `ambient kube-context: ${t?.kube ?? 'unset'}`
      const note = call.tool === 'helmfile' ? HELMFILE_NOTE : ''
      return { deny: `${PLUGIN}: refused, a command that changes a cluster must name its target with ${flag} (${ambient}).${note}` }
    }
  }
  return {}
}

type Ran = { deny?: string; text?: string; result?: unknown }

// Output carrying a Secret value this mod minted or read never reaches the
// model (which reads that the tool ran and a plugin withheld its result).
function withheld<R extends Ran>(ran: R): R | { deny: string } {
  if (ran.deny !== undefined || !hasKnown()) return ran
  if (!carriesKnown(ran.text ?? '') && !carriesKnownIn(ran.result)) return ran
  return { deny: `${PLUGIN}: the output carried a Secret value this guard manages, so it was withheld` }
}

// The secret tools' writes in the audit log beside the Bash ones.
async function recordSecretWrite($: Engine, tool: string, e: Record<string, unknown>, r: { deny?: string; result?: unknown }, started: number) {
  await record($, {
    at: new Date(started).toISOString(),
    session: await $.session.id(),
    cwd: await $.session.cwd(),
    command: `${tool} ${String(e.namespace)}/${String(e.secret)} key ${String(e.key)} on context ${String(e.context)}`.slice(0, 400),
    targets: await read($, targets),
    outcome: r.deny !== undefined ? 'refused' : 'ok',
    note: r.deny?.slice(0, 160),
    ms: (await $.clock.now()) - started,
  })
}

async function startWatch($: Engine, e: Record<string, unknown>) {
  const minutes = typeof e.timeoutMinutes === 'number' ? Math.min(Math.max(Math.round(e.timeoutMinutes), 1), 120) : 15
  let argv: string[]
  let label: string
  if (e.kind === 'rollout') {
    const { context, namespace, deployment, kubeconfig } = e
    if (typeof context !== 'string' || !CONTEXT.test(context)) return { deny: 'context must name a kubeconfig context' }
    if (typeof namespace !== 'string' || !DNS_NAME.test(namespace)) return { deny: 'namespace is not a valid name' }
    if (typeof deployment !== 'string' || !DNS_NAME.test(deployment)) return { deny: 'deployment is not a valid name' }
    if (kubeconfig !== undefined && (typeof kubeconfig !== 'string' || !kubeconfig.startsWith('/'))) return { deny: 'kubeconfig must be an absolute path' }
    const config = typeof kubeconfig === 'string' ? ['--kubeconfig', kubeconfig] : []
    argv = ['kubectl', ...config, '--context', context, '--namespace', namespace, 'rollout', 'status', `deployment/${deployment}`, '--watch=false']
    label = `rollout ${namespace}/${deployment} on ${context}`
  } else if (e.kind === 'gh-run') {
    const { repo, run } = e
    if (typeof repo !== 'string' || !REPO.test(repo)) return { deny: 'repo must be owner/name' }
    if (typeof run !== 'number' || !Number.isInteger(run) || run <= 0) return { deny: 'run must be a workflow run id' }
    argv = ['gh', 'run', 'view', String(run), '--repo', repo, '--json', 'status,conclusion']
    label = `gh run ${run} in ${repo}`
  } else return { deny: 'kind must be rollout or gh-run' }
  const now = await $.clock.now()
  const watch: Watch = {
    id: `w-${crypto.randomUUID().slice(0, 4)}`,
    kind: e.kind,
    label,
    argv,
    startedAt: now,
    deadline: now + minutes * 60_000,
    status: 'starting',
    state: 'running',
  }
  await update($, watches, all => {
    const finished = all.filter(x => x.state !== 'running').slice(-FINISHED_SHOWN)
    return [...all.filter(x => x.state === 'running'), ...finished, watch]
  })
  return {
    result:
      `Watching ${label} as ${watch.id}: the harness polls it every ${TICK_MS / 1000}s and gives up after ${minutes} min. ` +
      'A message arrives when it ends, so do not poll or sleep for it yourself.',
  }
}

// secret_set with no file: a field of the mod's own takes the value, so no
// dialog answer (which Claude Code sends to Anthropic while Remote Control is
// connected) carries it. The pane takes the keys at once where it is placed;
// else the band holds the field.
async function openPaste($: Engine, e: Record<string, unknown>) {
  const started = await startPaste($, e)
  if ('deny' in started) return started
  await update($, pending, () => ({ label: started.label, inPane: true }))
  const opened = await $.ui
    .open({ id: PASTE, title: `${PLUGIN}: paste a Secret value`, focus: true, closeOnEscape: true, holdToasts: true, rows: 5 })
    .catch(() => undefined)
  // No surface at all (a -p run): nobody could paste, so nothing is left waiting.
  if (opened === undefined || (!opened.isPlaced && opened.reason.startsWith('no-surface'))) {
    await update($, pending, () => null)
    // Not logged: nothing was asked of the person.
    await finishPaste($, undefined)
    return { deny: 'there is no screen to paste the value into here; ask the person to write it to a file and pass `file`' }
  }
  if (!opened.isPlaced) await update($, pending, p => p && { ...p, inPane: false })
  return {
    result:
      `Opened a field ${opened.isPlaced ? 'in a pane' : 'above the prompt (ctrl+x tab reaches it)'} where the person pastes the value for ` +
      `${started.label}. The value goes from that field to kubectl and is never shown to you. A message arrives when it is ` +
      'set or cancelled: do not ask for the value in chat, and do not poll or wait for it.',
  }
}

// Ends the paste: writes a pasted value or cancels, logs it, then tells Claude, never the value.
async function endPaste($: Engine, pasted: string | undefined, closePane: boolean) {
  if (!pastePending() || (pasted !== undefined && pasted.replace(/\r?\n$/, '') === '')) return
  await update($, pending, () => null)
  if (closePane) await $.ui.close({ id: PASTE })
  const started = await $.clock.now()
  const ended = await finishPaste($, pasted)
  if (ended === undefined) return
  const r = ended.written ? { result: ended.text } : { deny: ended.text }
  await recordSecretWrite($, 'secret_set', ended.call, r, started).catch(() => undefined)
  const note = ended.written && (await read($, scrubSkipped)) ? `\n${LEAK_NOTE}` : ''
  await $.prompt.submit({ text: `${PLUGIN}: ${ended.text}${note}` })
}

// The field itself, in the pane or the band. No `value` prop: the text stays in
// the field until Enter hands it to onSubmit, and is never drawn back.
function pasteField($: Engine, e: Parameters<Engine['ui']['resolve']>[0], p: PendingPaste, hint: string) {
  const table = $.ui.resolve(e)
  const { Box, Text, Button } = table
  // Not every surface has a field (mobile has none).
  const Input = 'Input' in table ? table.Input : undefined
  if (Input === undefined) return <Text color="warning">{`${PLUGIN}: paste the value for ${p.label} from a terminal session`}</Text>
  return (
    <Box flexDirection="column">
      <Text>{`Paste the new value for ${p.label}, then Enter. It goes to kubectl only; Claude never sees it.${hint}`}</Text>
      <Input key="secret-value" label="value" placeholder="paste here" autoFocus onSubmit={value => void endPaste($, value, true)} />
      <Button key="secret-cancel" label="Cancel" onPress={() => endPaste($, undefined, true)} />
    </Box>
  )
}

// A command line Claude runs, by Bash or as a Monitor's script: the gates,
// then the run, its audit row and a note when the targets changed.
async function guarded<R extends Ran & { isError?: true; context?: readonly string[] }>(
  $: Engine,
  command: string,
  toolUseId: string | undefined,
  run: () => Promise<R>,
  reads: ReadOptions,
  prod: RegExp,
) {
  const w = await where($)
  const found = calls(command, w.cwd, w.home)
  const runs = scriptRuns(command, w.cwd, w.home)
  if (found.length === 0 && runs.length === 0) return withheld(await run())

  const started = await $.clock.now()
  const before = (await read($, targets)) ?? (await refresh($))
  const asShown = shown(command)
  let gate = directGate(found, before, reads)
  if (gate.deny === undefined) gate = await terraformGate($, command, w, asShown)
  if (gate.deny === undefined && runs.length > 0) {
    const scripted = await scriptGate($, command, w, prod, asShown)
    gate = { deny: scripted.deny, confirmed: [gate.confirmed, scripted.confirmed].filter(Boolean).join('; ') || undefined }
  }
  // Approved in a dialog that showed the whole line, the call is not asked
  // about again (tool.check below); a line too long to show is.
  const id = gate.deny === undefined && gate.confirmed !== undefined && asShown.whole ? toolUseId : undefined
  if (id !== undefined) approved.add(id)
  const raw: R | { deny: string; isError?: undefined } =
    gate.deny === undefined ? await run().finally(() => id !== undefined && approved.delete(id)) : { deny: gate.deny }
  const confirmed =
    id !== undefined && overruled.delete(id)
      ? `${gate.confirmed}; the permission check asked, ${PLUGIN} allowed it`
      : gate.confirmed !== undefined && !asShown.whole
        ? `${gate.confirmed}; too long to show whole, left to the permission check`
        : gate.confirmed
  const ran = withheld(raw)
  const after = await refresh($)

  if (gate.deny !== undefined || found.some(c => isWrite(c) || switchesTarget(c)) || runs.length > 0) {
    await record($, {
      at: new Date(started).toISOString(),
      session: await $.session.id(),
      cwd: w.cwd,
      command: mask(scrub(command)),
      targets: before,
      outcome: raw.deny !== undefined ? 'refused' : raw.isError ? 'error' : gate.confirmed ? 'confirmed' : 'ok',
      note: raw.deny !== undefined ? raw.deny.slice(0, 160) : ran.deny !== undefined ? 'output withheld' : confirmed,
      ms: (await $.clock.now()) - started,
    })
  }

  if (ran.deny !== undefined) return ran
  // Not refused and not withheld: what the tool itself answered.
  const answered = ran as R
  const line = targetLine(after)
  if (line === announced) return answered
  announced = line
  return { ...answered, context: [...(answered.context ?? []), `${PLUGIN}: ambient targets now: ${line}`] }
}

// A Secret write in a session whose rows go unscrubbed tells Claude so.
async function noted<R extends { deny?: string; result?: unknown; context?: readonly string[] }>($: Engine, r: R) {
  if (r.deny !== undefined || !(await read($, scrubSkipped))) return r
  return { ...r, context: [...(r.context ?? []), LEAK_NOTE] }
}

// A call the person approved in a dialog here runs on that answer: an ask
// would go to the permission mode, in auto mode its classifier. A failure here
// is skipped, leaving the verdict beneath, which asks as it did before. Each
// allow is said in the transcript (not to Claude) and in the audit note.
async function allowApproved<V extends Parameters<typeof settle>[0]>($: Engine, id: string | undefined, verdict: V) {
  const settled = settle(verdict, id, approved)
  if (settled !== verdict && id !== undefined) {
    overruled.add(id)
    $.ui.log(`${PLUGIN}: allowed this command at the permission check, on your answer in its dialog`)
  }
  return settled
}

export const register: Register = (on, options) => {
  let prod = /prod|prd|production/i
  try {
    prod = new RegExp(String(options.prodPattern ?? prod.source), 'i')
  } catch {
    // An unreadable pattern keeps the default.
  }
  const reads: ReadOptions = { allowHelmGet: options.allowHelmGet === true }

  on('session.start', async ($, e, next) => {
    await $.tool.register({
      name: 'watch_start',
      description:
        'Hands a long-running operation to the harness to watch: a Deployment rollout or a GitHub Actions run. ' +
        'The harness polls it read-only, shows it to the person, and sends you a message when it ends; ' +
        'use this instead of sleep loops or repeated status commands.',
      inputSchema: {
        type: 'object',
        properties: {
          kind: { type: 'string', enum: ['rollout', 'gh-run'] },
          context: { type: 'string', description: 'rollout: kubeconfig context name' },
          kubeconfig: { type: 'string', description: 'rollout: absolute kubeconfig path; default kubectl\'s own' },
          namespace: { type: 'string', description: 'rollout' },
          deployment: { type: 'string', description: 'rollout: Deployment name' },
          repo: { type: 'string', description: 'gh-run: owner/name' },
          run: { type: 'integer', description: 'gh-run: workflow run id' },
          timeoutMinutes: { type: 'integer', minimum: 1, maximum: 120, description: 'default 15' },
        },
        required: ['kind'],
      },
      isDeferred: false,
    })
    await $.tool.register({
      name: 'watch_stop',
      description: 'Stops a watch started with watch_start.',
      inputSchema: { type: 'object', properties: { id: { type: 'string' } }, required: ['id'] },
      isDeferred: false,
    })
    const secretTarget = {
      kubeconfig: { type: 'string', description: 'absolute path of the kubeconfig file; default: kubectl\'s own' },
      context: { type: 'string', description: 'kubeconfig context name' },
      namespace: { type: 'string' },
      secret: { type: 'string', description: 'name of an existing Secret' },
    }
    await $.tool.register({
      name: 'secret_rotate',
      description:
        'Sets one key of an existing Kubernetes Secret to a new random value after the person confirms. ' +
        'The value is generated and written by the harness and is never shown to you; you get key names, sizes, ' +
        'fingerprints and whether the write was verified. Name the kube context explicitly.',
      inputSchema: {
        type: 'object',
        properties: {
          ...secretTarget,
          key: { type: 'string', description: 'key inside the Secret to set' },
          length: { type: 'integer', minimum: 16, maximum: 128, description: 'characters, default 32' },
        },
        required: ['context', 'namespace', 'secret', 'key'],
      },
      isDeferred: false,
    })
    await $.tool.register({
      name: 'secret_set',
      description:
        'Sets one key of an existing Kubernetes Secret to a value the person supplies (for a token a vendor issued). ' +
        'Without `file`, the harness opens a field where the person pastes the value, and returns at once; a message ' +
        'arrives when it is set or cancelled. With `file`, it reads a file the person wrote and asks them to confirm. ' +
        'The value goes to kubectl and is never shown to you: never ask for it in chat, and never read the file yourself.',
      inputSchema: {
        type: 'object',
        properties: {
          ...secretTarget,
          key: { type: 'string', description: 'key inside the Secret to set' },
          file: {
            type: 'string',
            description: 'only when the person wrote the value to a file: its absolute path; one trailing newline is dropped',
          },
        },
        required: ['context', 'namespace', 'secret', 'key'],
      },
      isDeferred: false,
    })
    await $.tool.register({
      name: 'secret_keys',
      description:
        'Lists the keys of a Kubernetes Secret with byte sizes and session-scoped fingerprints, never values. ' +
        'Two keys with the same fingerprint hold the same value.',
      inputSchema: { type: 'object', properties: secretTarget, required: ['context', 'namespace', 'secret'] },
      isDeferred: false,
    })
    await $.tool.register({
      name: 'leak_check',
      description:
        'Searches files for every Secret value this guard has minted or read in this session and answers only the names ' +
        'of files that hold one. Default folder: ~/.claude (transcripts, history, debug logs).',
      inputSchema: {
        type: 'object',
        properties: { paths: { type: 'array', items: { type: 'string' }, description: 'absolute folders or files' } },
      },
      isDeferred: false,
    })
    await $.command.register({ name: 'timeline', description: 'Infrastructure changes run from Claude Code, newest first', argumentHint: '[count]' })
    await refresh($)
    // A reload forgets the paste it was waiting for; its field goes with it.
    if ((await read($, pending)) !== null) {
      await update($, pending, () => null)
      await $.ui.close({ id: PASTE })
    }
    await update($, scrubSkipped, () => false)
    // A reload forgets the run under review and any approval; its pane goes too.
    if ((await read($, review)) !== null) {
      await update($, review, () => null)
      await $.ui.close({ id: REVIEW })
    }
    let ticks = 0
    $.clock.every(TICK_MS, () => void tick($, ++ticks % 3 === 0))
    return next(e)
  })

  on('tool.call', { tool: 'mcp__infra-guard__watch_start' }, ($, e) => startWatch($, e as Record<string, unknown>)).catch(() => ({
    deny: `${PLUGIN}: starting the watch failed`,
  }))

  on('tool.call', { tool: 'mcp__infra-guard__watch_stop' }, async ($, e) => {
    const id = (e as Record<string, unknown>).id
    const all = await read($, watches)
    if (!all.some(w => w.id === id && w.state === 'running')) return { deny: `no running watch ${String(id)}` }
    await setWatch($, String(id), { state: 'stopped', status: 'stopped', endedAt: await $.clock.now() })
    return { result: `stopped ${String(id)}` }
  }).catch(() => ({ deny: `${PLUGIN}: stopping the watch failed` }))

  on('tool.call', { tool: 'mcp__infra-guard__secret_rotate' }, async ($, e) => {
    const started = await $.clock.now()
    const r = await rotate($, e as Record<string, unknown>)
    await recordSecretWrite($, 'secret_rotate', e as Record<string, unknown>, r, started).catch(() => undefined)
    return noted($, r)
  }).catch(() => ({
    deny: `${PLUGIN}: the rotation failed before it reported`,
  }))
  on('tool.call', { tool: 'mcp__infra-guard__secret_set' }, async ($, e) => {
    const input = e as Record<string, unknown>
    const started = await $.clock.now()
    // An opened field is logged when the paste ends (endPaste); a refusal now.
    const r = input.file === undefined ? await openPaste($, input) : await setFromFile($, input)
    if (input.file !== undefined || 'deny' in r) await recordSecretWrite($, 'secret_set', input, r, started).catch(() => undefined)
    return input.file === undefined ? r : noted($, r)
  }).catch(() => ({
    deny: `${PLUGIN}: setting the value failed before it reported`,
  }))
  on('tool.call', { tool: 'mcp__infra-guard__secret_keys' }, ($, e) => listKeys($, e as Record<string, unknown>)).catch(() => ({
    deny: `${PLUGIN}: listing the keys failed`,
  }))
  on('tool.call', { tool: 'mcp__infra-guard__leak_check' }, ($, e) => leakCheck($, e as Record<string, unknown>)).catch(() => ({
    deny: `${PLUGIN}: the leak check failed`,
  }))

  on('command.run', { command: 'timeline' }, async ($, e) => {
    const n = Number.parseInt(e.args.trim() || '20', 10)
    const kept = ((await $.store.get(AUDIT_KEY)) as AuditEntry[] | undefined) ?? []
    return { text: timeline(kept, Number.isFinite(n) && n > 0 ? Math.min(n, 200) : 20) }
  })

  const checkFailed = `${PLUGIN}: its check failed, so the command was refused`
  // A check that failed before the command ran refuses it only when the line
  // could run an infra CLI or a script; any other runs, its output still checked.
  on('tool.call', { tool: 'Bash' }, ($, e, next) => guarded($, e.command, e.tool_use_id, () => next(e), reads, prod)).catch(async ($, e, next) =>
    next.called || !mentionsInfra(e.command) ? withheld(await next(e)) : { deny: checkFailed },
  )
  // A Monitor runs its command in the same shell as Bash; one that opens a
  // WebSocket runs none. Its events reach Claude as notifications (below).
  on('tool.call', { tool: 'Monitor' }, ($, e, next) =>
    e.command === undefined ? next(e) : guarded($, e.command, e.tool_use_id, () => next(e), reads, prod),
  ).catch(async ($, e, next) =>
    next.called || e.command === undefined || !mentionsInfra(e.command) ? withheld(await next(e)) : { deny: checkFailed },
  )

  on('tool.check', { tool: 'Bash' }, async ($, e, next) => allowApproved($, e.tool_use_id, await next(e)))
  on('tool.check', { tool: 'Monitor' }, async ($, e, next) => allowApproved($, e.tool_use_id, await next(e)))

  // Every other tool: output carrying a known value never reaches the model.
  on('tool.call', async ($, e, next) => {
    toolCalls++
    return e.tool === 'Bash' ? next(e) : withheld(await next(e))
  }).catch(() => ({
    deny: `${PLUGIN}: its output check failed, so the output was withheld`,
  }))

  // Each prompt submitted. One that starts a turn after tool calls none of
  // whose result rows came by says the scrub below is not running; a failure
  // in that judgment holds no prompt.
  // A background task's notification (a Monitor's events, a background
  // command's end) carrying a known value never reaches the model. Dropped
  // whole, not rewritten: the engine documents no rewrite of a notification
  // that starts a turn. Claude hears that one was,
  // from a dispatch of its own: a submit inside this hook would wait on itself.
  on('prompt.submit', async ($, e, next) => {
    try {
      if (e.turnId === undefined && toolCalls > 0 && resultRows === 0 && !(await read($, scrubSkipped))) await update($, scrubSkipped, () => true)
    } catch {
      // Judged again at the next turn.
    }
    if (e.origin?.kind !== 'task-notification' || !hasKnown() || !carriesKnown(e.text)) return next(e)
    $.clock.after(0, () => void $.prompt.submit({ text: `${PLUGIN}: a background task's notification carried a Secret value this guard manages, so it was withheld` }))
    return { drop: `${PLUGIN}: withheld a background task's notification that carried a Secret value` }
  }).catch(($, e, next) => (next.called || e.origin?.kind !== 'task-notification' ? next(e) : { drop: `${PLUGIN}: its notification check failed, so it was withheld` }))

  // Every stored row: a known value is replaced before it is kept or sent.
  on('session.append', ($, e, next) => {
    if (e.door === 'tool-result') resultRows++
    if (!hasKnown() || !carriesKnown(JSON.stringify(e.message.content))) return next(e)
    const content = e.message.content.map(block => {
      if (block.type === 'text' && typeof block.text === 'string') return { ...block, text: scrub(block.text) }
      if (block.type === 'tool_result') return JSON.parse(scrub(JSON.stringify(block)))
      return block
    })
    return next({ ...e, message: { ...e.message, content } })
  }).catch(($, e, next) => {
    // The scrub failed: keep the row's shape, none of its text.
    const content = e.message.content.map(block => {
      if (block.type === 'text') return { ...block, text: REDACTED }
      if (block.type === 'tool_result') return { ...block, content: REDACTED }
      return block
    })
    return next({ ...e, message: { ...e.message, content } })
  })

  // The person closing the paste pane (Esc, its close mark) cancels the paste.
  on('ui.close', async ($, e, next) => {
    if (e.id === PASTE && e.origin.kind === 'person') await endPaste($, undefined, false)
    if (e.id === REVIEW && e.origin.kind === 'person') await endReview($, false, false)
    return next(e)
  })

  on('ui.render', { component: 'Pane', requestId: PASTE }, async ($, e) => {
    const p = await read($, pending)
    const { Text } = $.ui.resolve(e)
    return p === null ? <Text dimColor>Nothing is waiting to be pasted.</Text> : pasteField($, e, p, ' Esc cancels.')
  })

  on('ui.render', { component: 'Pane', requestId: REVIEW }, async ($, e) => {
    const r = await read($, review)
    const { Text } = $.ui.resolve(e)
    return r === null ? <Text dimColor>Nothing is waiting for review.</Text> : reviewBody($, e, r)
  })

  on('ui.render', { component: 'AbovePrompt' }, async ($, e, next) => {
    if (e.props.hasSurvey) return next(e)
    const t = await read($, targets)
    const all = await read($, watches)
    const paste = await read($, pending)
    const skipped = await read($, scrubSkipped)
    const waiting = await read($, review)
    const shown = [...all.filter(w => w.state === 'running'), ...all.filter(w => w.state !== 'running').slice(-FINISHED_SHOWN)]
    const { Box, Text, Button } = $.ui.resolve(e)
    const part = (key: string, label: string, value: string | undefined) => {
      if (value === undefined) return null
      const isProd = prod.test(value)
      return (
        <Text key={key} color={isProd ? 'error' : 'subtle'} bold={isProd}>
          {`${label} ${value}${isProd ? ' PROD' : ''}   `}
        </Text>
      )
    }
    return (
      <Box flexDirection="column">
        <Box flexDirection="row">
          {part('kube', 'kube', t?.kube)}
          {part('gcloud', 'gcloud', t?.gcloud)}
          {part('gh', 'gh', t?.gh)}
          {part('aws', 'aws', t?.aws)}
          {part('argocd', 'argocd', t?.argocd)}
        </Box>
        {shown.map(w => (
          <Text key={w.id} color={w.state === 'running' ? 'suggestion' : w.state === 'done' ? 'success' : 'warning'}>
            {`${w.state === 'running' ? 'watching' : w.state} ${w.label}: ${w.status}`}
          </Text>
        ))}
        {skipped && (
          <Text key="scrub-off" color="warning">
            {`${PLUGIN}: transcript scrub is off, another plugin sends stored rows past this one. Run leak_check after Secret work.`}
          </Text>
        )}
        {paste !== null && !paste.inPane && pasteField($, e, paste, ' ctrl+x tab reaches the field.')}
        {waiting !== null && !waiting.inPane && (
          <Box key="review" flexDirection="row">
            <Text color="warning">{`${PLUGIN}: ${waiting.scripts.map(s => s.path).join(', ') || 'a script'} waits for your review (ctrl+x tab) `}</Text>
            <Button key="review-open" label="Review" hotkey="v" variant="primary" onPress={() => showReview($)} />
            <Button key="review-band-cancel" label="Cancel" onPress={() => endReview($, false, false)} />
          </Box>
        )}
      </Box>
    )
  })
}

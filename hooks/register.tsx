import { atom, read, update } from 'claude-code'
import type { EngineInterface, Register } from 'claude-code'
import type { AuditEntry, Targets, Watch } from '../types'
import { mask, targetLine, timeline } from './audit'
import { CONTEXT, DNS_NAME, REPO } from './names'
import { describeFindings, scanScript, type Finding } from './script'
import { carriesKnown, hasKnown, KEYS, leakCheck, listKeys, readsSecret, REDACTED, rotate, ROTATE, scrub, SET, writeKey } from './secrets'
import { calls, isWrite, namesTarget, scripts, switchesTarget, type Call } from './shell'
import { prodTargets, readTargets } from './targets'
import { describePlan, summarizePlan, terraformRuns } from './terraform'
import { ghRunProgress, rolloutProgress } from './watch'

// Guards for infra work from Claude Code:
// 1. the ambient targets in a band above the prompt, told to Claude when they
//    change; direct kubectl/helm changes must name their context, and
//    scripts are read before they run for commands that take the ambient one;
// 2. terraform apply only from a saved plan the person approved;
// 3. every infra change logged with the targets of the moment (/timeline);
// 4. read-only watches the mod polls itself, waking Claude when one ends;
// 5. Secret values the model never sees (secrets.ts): tools that write them,
//    commands that would print them refused, output carrying them withheld.

type Engine = EngineInterface
type Where = { cwd: string; home: string }
type Gate = { deny?: string; confirmed?: string }

const PLUGIN = 'infra-guard'
const AUDIT_KEY = 'audit'
const AUDIT_LIMIT = 1000
const TICK_MS = 5000
const FINISHED_SHOWN = 3
// Direct changes to a cluster must say which one; a script is asked about instead.
const CONTEXT_FLAG: Partial<Record<Call['tool'], string>> = { kubectl: 'kubectl --context', helm: 'helm --kube-context' }

const targets = atom({ plugin: 'infra-guard', key: 'targets' } as const, null as Targets | null)
const watches = atom({ plugin: 'infra-guard', key: 'watches' } as const, [] as Watch[])

// What Claude was last told of the targets: it hears again only on a change.
let announced = ''
const polling = new Set<string>()

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

async function terraformGate($: Engine, command: string, w: Where): Promise<Gate> {
  const confirmed: string[] = []
  for (const run of terraformRuns(command, w.cwd, w.home)) {
    if (run.verb === 'apply' && run.plan === undefined) {
      return {
        deny:
          `${PLUGIN}: refused terraform apply without a saved plan. Run \`terraform plan -out=tfplan\`, ` +
          'show the person what it changes, then `terraform apply tfplan`.',
      }
    }
    const dir = short(run.dir, w.home)
    if (run.verb === 'apply' && run.plan !== undefined) {
      const shown = await $.process.run(['terraform', 'show', '-json', run.plan], { cwd: run.dir, timeoutMs: 60_000 })
      if (shown.exitCode !== 0) return { deny: `${PLUGIN}: could not read the plan ${run.plan}: ${shown.stderr.trim().slice(0, 300)}` }
      const s = summarizePlan(JSON.parse(shown.stdout))
      const losses = [...s.replace, ...s.delete]
      const question = [
        `terraform apply ${run.plan} in ${dir}: ${describePlan(s)}.`,
        ...(losses.length > 0 ? [`Destroys: ${list(losses)}`] : []),
        'Apply it?',
      ].join('\n')
      if (!(await ask($, question, losses.length > 0 ? `Apply, destroying ${losses.length}` : 'Apply'))) {
        return { deny: `${PLUGIN}: the person did not approve the plan (${describePlan(s)})` }
      }
      confirmed.push(describePlan(s))
      continue
    }
    const state = await $.process.run(['terraform', 'state', 'list'], { cwd: run.dir, timeoutMs: 60_000 })
    const items = state.stdout.split('\n').filter(Boolean)
    const question = `terraform destroy in ${dir} deletes all ${items.length} resources in its state${items.length > 0 ? `: ${list(items)}` : ''}. Destroy?`
    if (!(await ask($, question, `Destroy ${items.length}`))) return { deny: `${PLUGIN}: the person did not approve terraform destroy` }
    confirmed.push(`destroy of ${items.length}`)
  }
  return confirmed.length > 0 ? { confirmed: confirmed.join('; ') } : {}
}

// Reads each script the line runs (and those it runs, two levels down).
async function scriptGate($: Engine, command: string, w: Where, t: Targets | null, prod: RegExp): Promise<Gate> {
  const queue = scripts(command, w.cwd, w.home).map(path => ({ path, depth: 0 }))
  const seen = new Set<string>()
  const findings: Finding[] = []
  const unread: string[] = []
  while (queue.length > 0) {
    const { path, depth } = queue.shift()!
    if (seen.has(path)) continue
    seen.add(path)
    let text: string
    try {
      text = await $.fs.read(path)
    } catch {
      unread.push(path)
      continue
    }
    const scan = scanScript(path, text, w.home)
    findings.push(...scan.findings)
    if (depth < 2) queue.push(...scan.nested.map(p => ({ path: p, depth: depth + 1 })))
  }
  if (findings.length === 0 && unread.length === 0) return {}
  const onProd = prodTargets(t, prod)
  const question = [
    `${seen.size} script(s) would run ${findings.length} command(s) that take the ambient target:`,
    ...describeFindings(findings, w.home),
    ...unread.map(p => `could not read ${short(p, w.home)} to check it`),
    `Ambient now: ${targetLine(t)}${onProd.length > 0 ? `  (PRODUCTION: ${onProd.join(', ')})` : ''}`,
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

function directGate(found: Call[], t: Targets | null): Gate {
  for (const call of found) {
    const why = readsSecret(call)
    if (why !== undefined) return { deny: `${PLUGIN}: refused, ${why}. List keys with ${KEYS}; change a value with ${ROTATE} or ${SET}.` }
  }
  for (const call of found) {
    const flag = CONTEXT_FLAG[call.tool]
    if (flag !== undefined && isWrite(call) && !namesTarget(call)) {
      return { deny: `${PLUGIN}: refused, a command that changes a cluster must name its target with ${flag} (ambient kube-context: ${t?.kube ?? 'unset'}).` }
    }
  }
  return {}
}

type Ran = { deny?: string; text?: string; result?: unknown }

// Output carrying a Secret value this mod minted or read never reaches the model.
function withheld<R extends Ran>(ran: R): R | { deny: string } {
  if (ran.deny !== undefined || !hasKnown()) return ran
  if (!carriesKnown(`${ran.text ?? ''}\n${JSON.stringify(ran.result ?? null)}`)) return ran
  return { deny: `${PLUGIN}: the output carried a Secret value this guard manages, so it was withheld` }
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

export const register: Register = (on, options) => {
  let prod = /prod|prd|production/i
  try {
    prod = new RegExp(String(options.prodPattern ?? prod.source), 'i')
  } catch {
    // An unreadable pattern keeps the default.
  }

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
        'Sets one key of an existing Kubernetes Secret to a value the person types into a dialog (for a token a vendor issued). ' +
        'The value goes from the dialog to kubectl and is never shown to you; you get the same report as secret_rotate.',
      inputSchema: {
        type: 'object',
        properties: { ...secretTarget, key: { type: 'string', description: 'key inside the Secret to set' } },
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

  on('tool.call', { tool: 'mcp__infra-guard__secret_rotate' }, ($, e) => rotate($, e as Record<string, unknown>)).catch(() => ({
    deny: `${PLUGIN}: the rotation failed before it reported`,
  }))
  on('tool.call', { tool: 'mcp__infra-guard__secret_set' }, ($, e) => writeKey($, e as Record<string, unknown>, { kind: 'typed' })).catch(() => ({
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

  on('tool.call', { tool: 'Bash' }, async ($, e, next) => {
    const w = await where($)
    const found = calls(e.command, w.cwd, w.home)
    const runs = scripts(e.command, w.cwd, w.home)
    if (found.length === 0 && runs.length === 0) return withheld(await next(e))

    const started = await $.clock.now()
    const before = (await read($, targets)) ?? (await refresh($))
    let gate = directGate(found, before)
    if (gate.deny === undefined) gate = await terraformGate($, e.command, w)
    if (gate.deny === undefined && runs.length > 0) {
      const scripted = await scriptGate($, e.command, w, before, prod)
      gate = { deny: scripted.deny, confirmed: [gate.confirmed, scripted.confirmed].filter(Boolean).join('; ') || undefined }
    }
    const raw = gate.deny === undefined ? await next(e) : { deny: gate.deny }
    const ran = withheld(raw)
    const after = await refresh($)

    if (gate.deny !== undefined || found.some(c => isWrite(c) || switchesTarget(c)) || runs.length > 0) {
      await record($, {
        at: new Date(started).toISOString(),
        session: await $.session.id(),
        cwd: w.cwd,
        command: mask(e.command),
        targets: before,
        outcome: raw.deny !== undefined ? 'refused' : raw.isError ? 'error' : gate.confirmed ? 'confirmed' : 'ok',
        note: raw.deny !== undefined ? raw.deny.slice(0, 160) : ran.deny !== undefined ? 'output withheld' : gate.confirmed,
        ms: (await $.clock.now()) - started,
      })
    }

    if (ran.deny !== undefined) return ran
    const line = targetLine(after)
    if (line === announced) return ran
    announced = line
    return { ...ran, context: [...(ran.context ?? []), `${PLUGIN}: ambient targets now: ${line}`] }
  }).catch(async ($, e, next) => (next.called ? withheld(await next(e)) : { deny: `${PLUGIN}: its check failed, so the command was refused` }))

  // Every other tool: output carrying a known value never reaches the model.
  on('tool.call', async ($, e, next) => (e.tool === 'Bash' ? next(e) : withheld(await next(e)))).catch(() => ({
    deny: `${PLUGIN}: its output check failed, so the output was withheld`,
  }))

  // Every stored row: a known value is replaced before it is kept or sent.
  on('session.append', ($, e, next) => {
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

  on('ui.render', { component: 'AbovePrompt' }, async ($, e, next) => {
    if (e.props.hasSurvey) return next(e)
    const t = await read($, targets)
    const all = await read($, watches)
    const shown = [...all.filter(w => w.state === 'running'), ...all.filter(w => w.state !== 'running').slice(-FINISHED_SHOWN)]
    const { Box, Text } = $.ui.resolve(e)
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
        </Box>
        {shown.map(w => (
          <Text key={w.id} color={w.state === 'running' ? 'suggestion' : w.state === 'done' ? 'success' : 'warning'}>
            {`${w.state === 'running' ? 'watching' : w.state} ${w.label}: ${w.status}`}
          </Text>
        ))}
      </Box>
    )
  })
}

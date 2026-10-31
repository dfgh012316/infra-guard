// Just enough shell reading to find which infra CLIs a command line runs and
// whether each names its target. Not a shell: no expansion, no aliases.

export type Tool = 'kubectl' | 'helm' | 'helmfile' | 'gcloud' | 'aws' | 'terraform' | 'tofu' | 'terragrunt' | 'gh' | 'argocd' | 'kubectx' | 'kubens'
export type Step = { words: string[]; cwd: string }
export type Call = { tool: Tool; args: string[]; env: string[]; cwd: string; text: string }
export type ScriptRun = { path: string; cwd: string }

const TOOLS = new Set<string>(['kubectl', 'helm', 'helmfile', 'gcloud', 'aws', 'terraform', 'tofu', 'terragrunt', 'gh', 'argocd', 'kubectx', 'kubens'])
// Drop-in replacements, read as the tool they stand in for.
const STANDS_FOR: Record<string, Tool> = { kubecolor: 'kubectl' }
const MENTIONS = new RegExp(`\\b(${[...TOOLS, ...Object.keys(STANDS_FOR)].join('|')})\\b|\\.(sh|bash)\\b`)

// Whether a line could run an infra CLI or a script, by its spelling alone:
// what the command check falls back on when reading the line failed.
export function mentionsInfra(line: string): boolean {
  return MENTIONS.test(line)
}
// Words that open a command without being it.
const KEYWORDS = new Set(['do', 'then', 'else', 'elif', 'if', 'while', 'until', '!', '{'])
// Commands that run the command after them, with the flags that take a value
// and the positionals (timeout's duration) that come before it.
const WRAPPERS: Record<string, { takes: string[]; positionals?: number }> = {
  sudo: { takes: ['-u', '-g', '-C', '-D', '-p', '-r', '-t', '-T', '-U'] },
  env: { takes: ['-u', '--unset', '-C', '--chdir', '-S', '--split-string'] },
  nice: { takes: ['-n', '--adjustment'] },
  nohup: { takes: [] },
  exec: { takes: ['-a'] },
  command: { takes: [] },
  time: { takes: ['-f', '--format', '-o', '--output'] },
  timeout: { takes: ['-s', '--signal', '-k', '--kill-after'], positionals: 1 },
  gtimeout: { takes: ['-s', '--signal', '-k', '--kill-after'], positionals: 1 },
  xargs: { takes: ['-I', '-n', '-P', '-L', '-d', '-E', '-s', '-a', '--arg-file', '--delimiter', '--max-args', '--max-procs', '--max-lines', '--replace'] },
  watch: { takes: ['-n', '--interval'] },
  k3s: { takes: [] },
}
// Commands that run a quoted word as a command line. Anywhere else a quoted
// word is data (a grep pattern, a commit message) unless it substitutes one.
const RUNNERS = new Set(['bash', 'sh', 'zsh', 'dash', 'ksh', 'ash', 'fish', 'eval', 'ssh', 'su'])

// Words of each simple command, split on unquoted ; & | ( ) ` and newlines.
export function simpleCommands(line: string): string[][] {
  const out: string[][] = []
  let words: string[] = []
  let word = ''
  let inWord = false
  let quote: string | null = null
  const endWord = () => {
    if (inWord) words.push(word)
    word = ''
    inWord = false
  }
  const endCommand = () => {
    endWord()
    if (words.length > 0) out.push(words)
    words = []
  }
  for (let i = 0; i < line.length; i++) {
    const c = line[i]!
    if (quote !== null) {
      if (c === quote) quote = null
      else if (c === '\\' && quote === '"' && i + 1 < line.length) word += line[++i]
      else word += c
      continue
    }
    if (c === "'" || c === '"') {
      quote = c
      inWord = true
    } else if (c === '\\' && i + 1 < line.length) {
      if (line[i + 1] === '\n') i++
      else {
        word += line[++i]
        inWord = true
      }
    } else if (';&|()`\n'.includes(c)) endCommand()
    else if (c === ' ' || c === '\t') endWord()
    else if (c === '#' && !inWord) {
      while (i < line.length && line[i] !== '\n') i++
      endCommand()
    } else {
      word += c
      inWord = true
    }
  }
  endCommand()
  return out
}

export function join(base: string, path: string): string {
  if (path.startsWith('/')) return normalize(path)
  return normalize(`${base}/${path}`)
}

function normalize(path: string): string {
  const parts: string[] = []
  for (const p of path.split('/')) {
    if (p === '' || p === '.') continue
    if (p === '..') parts.pop()
    else parts.push(p)
  }
  return `/${parts.join('/')}`
}

function isQuoted(line: string, index: number): boolean {
  let quote: string | null = null
  for (let i = 0; i < index; i++) {
    const c = line[i]!
    if (quote !== null) {
      if (c === quote) quote = null
      else if (c === '\\' && quote === '"') i++
    } else if (c === "'" || c === '"') quote = c
    else if (c === '\\') i++
  }
  return quote !== null
}

// Heredoc bodies are data, not commands (a script written with `cat <<EOF`
// is not run): each body line becomes empty, so line numbers stay put.
export function withoutHeredocs(text: string): string {
  const out: string[] = []
  const pending: { word: string; tabs: boolean }[] = []
  for (const line of text.split('\n')) {
    const body = pending[0]
    if (body !== undefined) {
      if ((body.tabs ? line.replace(/^\t+/, '') : line) === body.word) pending.shift()
      out.push('')
      continue
    }
    out.push(line)
    for (const m of line.matchAll(/<<(-?)\s*(['"]?)([A-Za-z_][A-Za-z0-9_]*)\2/g)) {
      if (line[m.index - 1] === '<' || isQuoted(line, m.index)) continue
      pending.push({ word: m[3]!, tabs: m[1] === '-' })
    }
  }
  return out.join('\n')
}

// Simple commands with the directory each runs in, following `cd`.
export function steps(line: string, cwd: string, home: string): Step[] {
  let dir = cwd
  return simpleCommands(withoutHeredocs(line)).map(words => {
    if (words[0] === 'cd' && words[1] !== undefined) {
      dir = words[1].startsWith('~/') ? join(home, words[1].slice(2)) : join(dir, words[1])
    }
    return { words, cwd: dir }
  })
}

// Where a simple command's command word is: past assignments (collected into
// `env`), keywords, and wrappers with their flags.
function commandIndex(words: string[], env: string[]): number {
  let i = 0
  while (i < words.length) {
    const w = words[i]!
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(w)) env.push(w)
    else if (!KEYWORDS.has(w)) {
      const wrapper = Object.hasOwn(WRAPPERS, w) ? WRAPPERS[w]! : undefined
      if (wrapper === undefined) return i
      while (words[i + 1]?.startsWith('-')) {
        const flag = words[++i]!
        if (flag === '--') break
        if (wrapper.takes.includes(flag)) i++
      }
      i += wrapper.positionals ?? 0
    }
    i++
  }
  return i
}

// The infra CLI calls in a line, also inside quoted words a shell or ssh runs
// (`ssh host '...'`, `bash -c '...'`) or that substitute a command (`"$(...)"`),
// two levels deep.
export function calls(line: string, cwd: string, home: string, depth = 0): Call[] {
  const found: Call[] = []
  for (const step of steps(line, cwd, home)) {
    const { words } = step
    const env: string[] = []
    const at = commandIndex(words, env)
    const name = words[at]?.split('/').at(-1) ?? ''
    const tool = Object.hasOwn(STANDS_FOR, name) ? STANDS_FOR[name]! : name
    if (TOOLS.has(tool)) {
      found.push({ tool: tool as Tool, args: words.slice(at + 1), env, cwd: step.cwd, text: words.slice(at).join(' ') })
    }
    if (depth >= 2) continue
    // `-c` runs its word only after a shell (`docker exec c sh -c '...'`); for
    // grep and most other commands it is a flag of their own.
    const shellAt = (j: number) => words.slice(at, j - 1).some(x => RUNNERS.has(x.split('/').at(-1) ?? ''))
    words.forEach((w, j) => {
      if (!/\s/.test(w)) return
      const afterFlag = ['-c', '--command'].includes(words[j - 1] ?? '') && shellAt(j)
      const runs = RUNNERS.has(name) || j === at || afterFlag || /\$\(|`/.test(w)
      if (runs) found.push(...calls(w, step.cwd, home, depth + 1))
    })
  }
  return found
}

const TERRAFORM_VALUES = ['-var', '-var-file', '-target', '-state', '-state-out', '-backup', '-lock-timeout', '-parallelism']
const VALUE_FLAGS: Record<Tool, Set<string>> = {
  kubectl: new Set([
    '-n', '--namespace', '--context', '--kubeconfig', '--cluster', '--user', '-s', '--server', '-l', '--selector', '-o', '--output', '-f', '--filename', '-c', '--container',
    '--as', '--as-group', '--as-uid', '--request-timeout', '--token', '--certificate-authority', '--client-certificate', '--client-key', '--tls-server-name', '--cache-dir',
    '-v', '--v', '--log-file', '-p', '--patch', '--type', '--image', '--replicas', '--field-manager', '--timeout', '--for', '--template', '-k', '--kustomize', '--sort-by',
    '--field-selector', '-L', '--label-columns', '--from-literal', '--from-file', '--from-env-file', '--overrides', '--restart', '--port',
  ]),
  helm: new Set([
    '-n', '--namespace', '--kube-context', '--kubeconfig', '-f', '--values', '--set', '--version', '-o', '--output', '--timeout', '--set-string', '--set-file', '--set-json',
    '--set-literal', '--description', '--repo', '--post-renderer', '--post-renderer-args', '--revision', '--kube-apiserver', '--kube-token', '--kube-as-user', '--kube-as-group',
    '--kube-ca-file', '--kube-tls-server-name', '--burst-limit', '--qps', '--registry-config', '--repository-cache', '--repository-config', '--history-max', '--max', '--template',
    '--username', '--password', '--ca-file', '--cert-file', '--key-file',
  ]),
  helmfile: new Set([
    '-f', '--file', '-e', '--environment', '-l', '--selector', '-n', '--namespace', '--kube-context', '-b', '--helm-binary', '-k', '--kustomize-binary', '-c', '--chart',
    '--log-level', '--state-values-file', '--state-values-set', '--state-values-set-string', '--set', '--values', '--concurrency', '--args', '--context', '--output',
  ]),
  gcloud: new Set(['--project', '--account', '--configuration', '--format', '--region', '--zone', '--secret', '--location', '--impersonate-service-account', '--billing-project']),
  aws: new Set(['--profile', '--region', '--output', '--query']),
  terraform: new Set(TERRAFORM_VALUES),
  tofu: new Set(TERRAFORM_VALUES),
  terragrunt: new Set([
    ...TERRAFORM_VALUES, '--terragrunt-working-dir', '--working-dir', '--terragrunt-config', '--config', '--terragrunt-include-dir', '--queue-include-dir',
    '--terragrunt-exclude-dir', '--queue-exclude-dir', '--terragrunt-iam-role', '--iam-assume-role', '--terragrunt-log-level', '--log-level', '--terragrunt-source', '--source',
    '--terragrunt-parallelism', '--parallelism', '--terragrunt-download-dir', '--download-dir',
  ]),
  gh: new Set(['-R', '--repo', '-b', '--body', '-t', '--title']),
  argocd: new Set([
    '--server', '--argocd-context', '--config', '--auth-token', '--grpc-web-root-path', '--header', '-H', '--port-forward-namespace', '--loglevel', '--logformat', '--client-crt',
    '--client-crt-key', '--server-crt', '--server-name', '--http-retry-max', '--kube-context', '-o', '--output', '--revision', '--resource', '-l', '--selector', '--timeout',
    '--retry-limit', '--retry-backoff-duration', '--strategy', '--project', '--app-namespace', '-N', '-p', '--parameter', '--dest-namespace', '--dest-server', '--dest-name',
    '--repo', '--path', '--sync-policy', '--label', '--local', '--source-position', '--source-name', '--group', '--kind', '--namespace', '--name',
  ]),
  kubectx: new Set(),
  kubens: new Set(),
}

// Positional words, flags and their values left out.
export function positionals(call: Call): string[] {
  const out: string[] = []
  const takes = VALUE_FLAGS[call.tool]
  for (let i = 0; i < call.args.length; i++) {
    const a = call.args[i]!
    if (a.startsWith('-')) {
      if (!a.includes('=') && takes.has(a)) i++
      continue
    }
    out.push(a)
  }
  return out
}

function hasFlag(call: Call, ...flags: string[]): boolean {
  return call.args.some(a => flags.some(f => a === f || a.startsWith(`${f}=`)))
}

function hasEnv(call: Call, ...names: string[]): boolean {
  return call.env.some(e => names.some(n => e.startsWith(`${n}=`)))
}

// terraform, OpenTofu (its fork, with the same words) and terragrunt, which runs either.
export function isTerraform(call: Call): call is Call & { tool: 'terraform' | 'tofu' | 'terragrunt' } {
  return call.tool === 'terraform' || call.tool === 'tofu' || call.tool === 'terragrunt'
}

// The terraform words of a call: terragrunt's `run-all apply` and
// `run --all -- apply` are `apply`.
export function terraformWords(call: Call): string[] {
  const p = positionals(call)
  return call.tool === 'terragrunt' && (p[0] === 'run-all' || p[0] === 'run') ? p.slice(1) : p
}

const KUBECTL_WRITES = new Set(['apply', 'create', 'delete', 'patch', 'replace', 'scale', 'set', 'label', 'annotate', 'edit', 'drain', 'cordon', 'uncordon', 'taint', 'expose', 'autoscale', 'run', 'exec', 'cp', 'debug', 'attach', 'certificate'])
const HELM_WRITES = new Set(['install', 'upgrade', 'uninstall', 'rollback', 'delete', 'test'])
const HELMFILE_WRITES = new Set(['apply', 'sync', 'destroy', 'delete', 'test'])
const GCLOUD_WRITES = new Set(['create', 'delete', 'update', 'deploy', 'resize', 'patch', 'import', 'apply', 'set-iam-policy', 'add-iam-policy-binding', 'remove-iam-policy-binding'])
const AWS_WRITE = /^(create|delete|put|update|modify|terminate|run|start|stop|reboot|attach|detach|associate|disassociate|register|deregister|remove|add|set|import|restore|invoke)-/
const TERRAFORM_WRITES = new Set(['apply', 'destroy', 'import', 'taint', 'untaint', 'force-unlock'])
const ARGOCD_WRITES = new Set(['create', 'delete', 'set', 'unset', 'sync', 'rollback', 'patch', 'patch-resource', 'delete-resource', 'terminate-op', 'edit', 'update', 'add', 'rm', 'remove', 'run', 'rotate-auth', 'update-password', 'generate-token'])

// Whether the call changes something outside this machine.
export function isWrite(call: Call): boolean {
  const p = positionals(call)
  switch (call.tool) {
    case 'kubectl':
      if (p[0] === 'rollout') return p[1] !== 'status' && p[1] !== 'history'
      if (p[0] === 'auth') return p[1] === 'reconcile'
      return KUBECTL_WRITES.has(p[0] ?? '')
    case 'helm':
      return HELM_WRITES.has(p[0] ?? '')
    case 'helmfile':
      return HELMFILE_WRITES.has(p[0] ?? '')
    case 'gcloud':
      return p[0] !== 'config' && p[0] !== 'auth' && p.some(w => GCLOUD_WRITES.has(w))
    case 'aws':
      return AWS_WRITE.test(p[1] ?? '') || (p[0] === 's3' && ['rm', 'cp', 'mv', 'sync', 'rb', 'mb'].includes(p[1] ?? ''))
    case 'terraform':
    case 'tofu':
    case 'terragrunt': {
      const t = terraformWords(call)
      return TERRAFORM_WRITES.has(t[0] ?? '') || (t[0] === 'state' && ['rm', 'mv', 'push'].includes(t[1] ?? ''))
    }
    case 'gh':
      return (
        (p[0] === 'workflow' && p[1] === 'run') ||
        (p[0] === 'release' && ['create', 'delete'].includes(p[1] ?? '')) ||
        (p[0] === 'pr' && p[1] === 'merge') ||
        (p[0] === 'secret' && ['set', 'delete'].includes(p[1] ?? ''))
      )
    case 'argocd':
      // `app sync`, `app actions run`, `proj role create-token`, `repo add`, ...
      return p.slice(1, 3).some(w => ARGOCD_WRITES.has(w) || /^(add|remove|set|delete|create|update)-/.test(w))
    case 'kubectx':
    case 'kubens':
      // They edit the kubeconfig only (switchesTarget).
      return false
  }
}

// Whether the call names where it acts, instead of taking the ambient one.
// A kubeconfig (or argocd config) file alone does not: its current context is still ambient.
export function namesTarget(call: Call): boolean {
  switch (call.tool) {
    case 'kubectl':
      return hasFlag(call, '--context')
    case 'helm':
    case 'helmfile':
      return hasFlag(call, '--kube-context') || hasEnv(call, 'HELM_KUBECONTEXT')
    case 'gcloud':
      return hasFlag(call, '--project') || hasEnv(call, 'CLOUDSDK_CORE_PROJECT')
    case 'aws':
      return hasFlag(call, '--profile') || hasEnv(call, 'AWS_PROFILE')
    case 'gh':
      return hasFlag(call, '-R', '--repo') || hasEnv(call, 'GH_REPO')
    case 'argocd':
      return hasFlag(call, '--argocd-context', '--server') || hasEnv(call, 'ARGOCD_SERVER')
    case 'terraform':
    case 'tofu':
    case 'terragrunt':
      return true
    case 'kubectx':
    case 'kubens':
      return false
  }
}

// Calls that change which target later commands take.
export function switchesTarget(call: Call): boolean {
  const p = positionals(call)
  if (call.tool === 'kubectl') return p[0] === 'config' && (p[1] === 'use-context' || (p[1] === 'set-context' && hasFlag(call, '--current')))
  if (call.tool === 'gcloud') return p[0] === 'config' && ((p[1] === 'set' && p[2] === 'project') || (p[1] === 'configurations' && p[2] === 'activate'))
  if (call.tool === 'gh') return p[0] === 'auth' && p[1] === 'switch'
  if (call.tool === 'argocd') return p[0] === 'login' || (p[0] === 'context' && p[1] !== undefined && !hasFlag(call, '--delete'))
  if (call.tool === 'kubectx' || call.tool === 'kubens') {
    // `kubectx NAME`, `kubectx -` (the previous one) and `-u` switch; `-c`
    // prints, `-d` deletes, `NEW=OLD` renames, and no argument lists.
    if (hasFlag(call, '-u', '--unset')) return true
    if (hasFlag(call, '-c', '--current', '-d', '--delete', '-h', '--help', '-V', '--version')) return false
    return call.args.includes('-') || p.some(w => !w.includes('='))
  }
  return false
}

// Scripts a line runs (`./x.sh`, `bash x.sh`, `source x.sh`, also behind a
// wrapper), each with the directory it is started from.
export function scriptRuns(line: string, cwd: string, home: string): ScriptRun[] {
  const found: ScriptRun[] = []
  for (const { words, cwd: dir } of steps(line, cwd, home)) {
    const at = commandIndex(words, [])
    const first = words[at] ?? ''
    const operand = words.slice(at + 1).find(w => !w.startsWith('-'))
    const path =
      /\.(sh|bash)$/.test(first) && first.includes('/')
        ? first
        : ['bash', 'sh', 'zsh', 'source', '.'].includes(first) && /\.(sh|bash)$/.test(operand ?? '')
          ? operand!
          : undefined
    if (path !== undefined) found.push({ path: path.startsWith('~/') ? join(home, path.slice(2)) : join(dir, path), cwd: dir })
  }
  return found
}

export function scripts(line: string, cwd: string, home: string): string[] {
  return scriptRuns(line, cwd, home).map(r => r.path)
}

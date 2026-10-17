// Just enough shell reading to find which infra CLIs a command line runs and
// whether each names its target. Not a shell: no expansion, no aliases.

export type Tool = 'kubectl' | 'helm' | 'gcloud' | 'aws' | 'terraform' | 'gh'
export type Step = { words: string[]; cwd: string }
export type Call = { tool: Tool; args: string[]; env: string[]; cwd: string; text: string }

const TOOLS = new Set<string>(['kubectl', 'helm', 'gcloud', 'aws', 'terraform', 'gh'])
const WRAPPERS = new Set(['sudo', 'env', 'time', 'nice', 'nohup', 'exec', 'command', 'k3s'])

// Words of each simple command, split on unquoted ; & | ( ) and newlines.
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
    } else if (';&|()\n'.includes(c)) endCommand()
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

// The infra CLI calls in a line, also inside quoted words (`ssh host '...'`,
// `bash -c '...'`), two levels deep.
export function calls(line: string, cwd: string, home: string, depth = 0): Call[] {
  const found: Call[] = []
  for (const step of steps(line, cwd, home)) {
    const { words } = step
    const env: string[] = []
    let i = 0
    while (i < words.length) {
      const w = words[i]!
      if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(w)) env.push(w)
      else if (!WRAPPERS.has(w) && !(w.startsWith('-') && i > 0 && WRAPPERS.has(words[i - 1]!))) break
      i++
    }
    const name = words[i]?.split('/').at(-1)
    if (name !== undefined && TOOLS.has(name)) {
      found.push({ tool: name as Tool, args: words.slice(i + 1), env, cwd: step.cwd, text: words.slice(i).join(' ') })
    }
    if (depth < 2) for (const w of words) if (/\s/.test(w)) found.push(...calls(w, step.cwd, home, depth + 1))
  }
  return found
}

const VALUE_FLAGS: Record<Tool, Set<string>> = {
  kubectl: new Set(['-n', '--namespace', '--context', '--kubeconfig', '--cluster', '--user', '-s', '--server', '-l', '--selector', '-o', '--output', '-f', '--filename', '-c', '--container']),
  helm: new Set(['-n', '--namespace', '--kube-context', '--kubeconfig', '-f', '--values', '--set', '--version', '-o', '--output']),
  gcloud: new Set(['--project', '--account', '--configuration', '--format', '--region', '--zone']),
  aws: new Set(['--profile', '--region', '--output', '--query']),
  terraform: new Set(['-var', '-var-file', '-target', '-state', '-state-out', '-backup', '-lock-timeout', '-parallelism']),
  gh: new Set(['-R', '--repo', '-b', '--body', '-t', '--title']),
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

const KUBECTL_WRITES = new Set(['apply', 'create', 'delete', 'patch', 'replace', 'scale', 'set', 'label', 'annotate', 'edit', 'drain', 'cordon', 'uncordon', 'taint', 'expose', 'autoscale', 'run'])
const HELM_WRITES = new Set(['install', 'upgrade', 'uninstall', 'rollback', 'delete'])
const GCLOUD_WRITES = new Set(['create', 'delete', 'update', 'deploy', 'resize', 'patch', 'import', 'apply', 'set-iam-policy', 'add-iam-policy-binding', 'remove-iam-policy-binding'])
const AWS_WRITE = /^(create|delete|put|update|modify|terminate|run|start|stop|reboot|attach|detach|associate|disassociate|register|deregister|remove|add|set|import|restore|invoke)-/
const TERRAFORM_WRITES = new Set(['apply', 'destroy', 'import', 'taint', 'untaint', 'force-unlock'])

// Whether the call changes something outside this machine.
export function isWrite(call: Call): boolean {
  const p = positionals(call)
  switch (call.tool) {
    case 'kubectl':
      if (p[0] === 'rollout') return p[1] !== 'status' && p[1] !== 'history'
      return KUBECTL_WRITES.has(p[0] ?? '')
    case 'helm':
      return HELM_WRITES.has(p[0] ?? '')
    case 'gcloud':
      return p[0] !== 'config' && p[0] !== 'auth' && p.some(w => GCLOUD_WRITES.has(w))
    case 'aws':
      return AWS_WRITE.test(p[1] ?? '') || (p[0] === 's3' && ['rm', 'cp', 'mv', 'sync', 'rb', 'mb'].includes(p[1] ?? ''))
    case 'terraform':
      return TERRAFORM_WRITES.has(p[0] ?? '') || (p[0] === 'state' && ['rm', 'mv', 'push'].includes(p[1] ?? ''))
    case 'gh':
      return (
        (p[0] === 'workflow' && p[1] === 'run') ||
        (p[0] === 'release' && ['create', 'delete'].includes(p[1] ?? '')) ||
        (p[0] === 'pr' && p[1] === 'merge') ||
        (p[0] === 'secret' && ['set', 'delete'].includes(p[1] ?? ''))
      )
  }
}

// Whether the call names where it acts, instead of taking the ambient one.
// A kubeconfig file alone does not: its current-context is still ambient.
export function namesTarget(call: Call): boolean {
  switch (call.tool) {
    case 'kubectl':
      return hasFlag(call, '--context')
    case 'helm':
      return hasFlag(call, '--kube-context') || hasEnv(call, 'HELM_KUBECONTEXT')
    case 'gcloud':
      return hasFlag(call, '--project') || hasEnv(call, 'CLOUDSDK_CORE_PROJECT')
    case 'aws':
      return hasFlag(call, '--profile') || hasEnv(call, 'AWS_PROFILE')
    case 'gh':
      return hasFlag(call, '-R', '--repo') || hasEnv(call, 'GH_REPO')
    case 'terraform':
      return true
  }
}

// Calls that change which target later commands take.
export function switchesTarget(call: Call): boolean {
  const p = positionals(call)
  if (call.tool === 'kubectl') return p[0] === 'config' && (p[1] === 'use-context' || (p[1] === 'set-context' && hasFlag(call, '--current')))
  if (call.tool === 'gcloud') return p[0] === 'config' && ((p[1] === 'set' && p[2] === 'project') || (p[1] === 'configurations' && p[2] === 'activate'))
  if (call.tool === 'gh') return p[0] === 'auth' && p[1] === 'switch'
  return false
}

// Scripts a line runs: `./x.sh`, `bash x.sh`, `source x.sh`, with their directory.
export function scripts(line: string, cwd: string, home: string): string[] {
  const found: string[] = []
  for (const { words, cwd: dir } of steps(line, cwd, home)) {
    const first = words[0] ?? ''
    const path = /\.(sh|bash)$/.test(first) && first.includes('/') ? first : ['bash', 'sh', 'zsh', 'source', '.'].includes(first) && /\.(sh|bash)$/.test(words[1] ?? '') ? words[1]! : undefined
    if (path !== undefined) found.push(path.startsWith('~/') ? join(home, path.slice(2)) : join(dir, path))
  }
  return found
}

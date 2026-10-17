import type { EngineInterface } from 'claude-code'
import { CONTEXT, DNS_NAME, SECRET_KEY } from './names'
import { positionals, type Call } from './shell'

// Kubernetes Secret values the model never sees.
//
// - secret_rotate mints a random value and writes it to a key of an existing
//   Secret once the person confirms; secret_set reads one from a file the
//   person wrote. Either way the value reaches kubectl through stdin and the
//   model gets key names, sizes and fingerprints only.
// - Every value minted or read here is kept in module memory, so output that
//   carries one is withheld and stored rows carrying one are scrubbed.

type Engine = EngineInterface
type Target = { kubeconfig?: string; context: string; namespace: string; secret: string }
type Source = { kind: 'random'; length: number } | { kind: 'file'; path: string }
type SecretObject = {
  type?: string
  data?: Record<string, string>
  metadata?: { resourceVersion?: string; annotations?: Record<string, string> }
}

export const ROTATE = 'mcp__infra-guard__secret_rotate'
export const SET = 'mcp__infra-guard__secret_set'
export const KEYS = 'mcp__infra-guard__secret_keys'
export const REDACTED = '[infra-guard: redacted]'

const LAST_APPLIED = 'kubectl.kubernetes.io/last-applied-configuration'
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
// Shorter values ("true", "5432") would withhold ordinary output.
const MIN_TRACKED = 8

// Every value this load minted or read, plain and base64. Module memory only.
const known = new Set<string>()
// Per-load salt, never shown: fingerprints compare values within a session,
// and a short password cannot be recovered from one offline.
const salt = crypto.getRandomValues(new Uint8Array(32))

function track(value: string) {
  if (value.length < MIN_TRACKED) return
  known.add(value)
  known.add(btoa(value))
}

export function hasKnown(): boolean {
  return known.size > 0
}

export function carriesKnown(text: string): boolean {
  for (const value of known) if (text.includes(value)) return true
  return false
}

export function scrub(text: string): string {
  let out = text
  for (const value of known) out = out.split(value).join(REDACTED)
  return out
}

function mint(length: number): string {
  let out = ''
  const bytes = new Uint8Array(length * 2)
  while (out.length < length) {
    crypto.getRandomValues(bytes)
    // 248 = 4 * 62: rejecting the rest keeps every character equally likely.
    for (const b of bytes) if (b < 248 && out.length < length) out += ALPHABET[b % 62]
  }
  return out
}

async function fingerprint(binary: string): Promise<string> {
  const data = new Uint8Array(salt.length + binary.length)
  data.set(salt)
  data.set(Uint8Array.from(binary, c => c.charCodeAt(0)), salt.length)
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', data))
  return [...digest.slice(0, 6)].map(b => b.toString(16).padStart(2, '0')).join('')
}

function target(e: Record<string, unknown>): Target | string {
  const { kubeconfig, context, namespace, secret } = e
  if (kubeconfig !== undefined && (typeof kubeconfig !== 'string' || !kubeconfig.startsWith('/'))) {
    return 'kubeconfig must be an absolute path'
  }
  if (typeof context !== 'string' || !CONTEXT.test(context)) return 'context must name a kubeconfig context'
  if (typeof namespace !== 'string' || !DNS_NAME.test(namespace)) return 'namespace is not a valid name'
  if (typeof secret !== 'string' || !DNS_NAME.test(secret)) return 'secret is not a valid name'
  return { ...(kubeconfig === undefined ? {} : { kubeconfig }), context, namespace, secret }
}

function where(t: Target): string {
  return `${t.namespace}/${t.secret} on context ${t.context}${t.kubeconfig ? ` (${t.kubeconfig})` : ''}`
}

function kubectl($: Engine, t: Target, args: string[], stdin?: string) {
  const config = t.kubeconfig ? ['--kubeconfig', t.kubeconfig] : []
  const argv = ['kubectl', ...config, '--context', t.context, '--namespace', t.namespace, ...args]
  return $.process.run(argv, stdin === undefined ? undefined : { stdin })
}

async function readSecret($: Engine, t: Target): Promise<SecretObject | string> {
  const got = await kubectl($, t, ['get', 'secret', t.secret, '--output', 'json'])
  if (got.exitCode !== 0) return `kubectl get failed: ${scrub(got.stderr).trim().slice(0, 500)}`
  const secret = JSON.parse(got.stdout) as SecretObject
  for (const value of Object.values(secret.data ?? {})) track(atob(value))
  return secret
}

async function summary(secret: SecretObject) {
  const keys = await Promise.all(
    Object.entries(secret.data ?? {}).map(async ([key, value]) => {
      const plain = atob(value)
      return { key, bytes: plain.length, fingerprint: await fingerprint(plain) }
    }),
  )
  const warnings =
    secret.metadata?.annotations?.[LAST_APPLIED] === undefined
      ? []
      : [`the ${LAST_APPLIED} annotation holds a plaintext copy of the values as of the last kubectl apply`]
  return { type: secret.type, resourceVersion: secret.metadata?.resourceVersion, keys, warnings }
}

export async function listKeys($: Engine, e: Record<string, unknown>) {
  const t = target(e)
  if (typeof t === 'string') return { deny: t }
  const secret = await readSecret($, t)
  if (typeof secret === 'string') return { deny: secret }
  return { result: JSON.stringify({ ...t, ...(await summary(secret)) }, null, 2) }
}

// The value comes from the mod (random) or from a file the person wrote; either
// way it reaches kubectl through stdin alone. Never from a dialog answer:
// Claude Code sends answers to Anthropic in the session's event stream, though
// they never reach the model.
async function obtain($: Engine, t: Target, key: string, source: Source): Promise<string | { deny: string }> {
  let fromFile = ''
  if (source.kind === 'file') {
    try {
      // One trailing newline is the file's, not the value's.
      fromFile = (await $.fs.read(source.path)).replace(/\r?\n$/, '')
    } catch {
      return { deny: `could not read ${source.path}` }
    }
    if (fromFile === '') return { deny: `${source.path} holds no value` }
    // Known from here on, even if the person cancels.
    track(fromFile)
  }
  try {
    if (source.kind === 'random') {
      const answer = await $.ui.ask(`Set ${key} in Secret ${where(t)} to a new random ${source.length}-character value?`, {
        header: 'Secret',
        options: ['Rotate', 'Cancel'],
      })
      return answer === 'Rotate' ? mint(source.length) : { deny: 'the person did not confirm the change' }
    }
    const size = `${fromFile.length} characters, fingerprint ${await fingerprint(fromFile)}`
    const answer = await $.ui.ask(`Set ${key} in Secret ${where(t)} to the value in ${source.path} (${size})?`, {
      header: 'Secret',
      options: ['Set', 'Cancel'],
    })
    return answer === 'Set' ? fromFile : { deny: 'the person did not confirm the change' }
  } catch {
    return { deny: 'changing a Secret needs a person in an interactive session' }
  }
}

export async function writeKey($: Engine, e: Record<string, unknown>, source: Source) {
  const t = target(e)
  if (typeof t === 'string') return { deny: t }
  const key = e.key
  if (typeof key !== 'string' || !SECRET_KEY.test(key)) return { deny: 'key is not a valid Secret key' }

  const before = await readSecret($, t)
  if (typeof before === 'string') return { deny: before }

  const value = await obtain($, t, key, source)
  if (typeof value !== 'string') return value
  track(value)
  // The host hands stdin over a socket, which kubectl cannot open as
  // /dev/stdin; `-f -` reads it as a stream. `replace` also refuses the write
  // when the Secret changed since it was read (resourceVersion).
  const updated = { ...before, data: { ...before.data, [key]: btoa(value) } }
  const replaced = await kubectl($, t, ['replace', '--filename', '-'], JSON.stringify(updated))
  if (replaced.exitCode !== 0) return { deny: `kubectl replace failed: ${scrub(replaced.stderr).trim().slice(0, 500)}` }

  const after = await readSecret($, t)
  if (typeof after === 'string') return { deny: `written, but reading it back failed: ${after}` }
  const verified = after.data?.[key] === btoa(value)
  const report = { ...t, key, written: true, verified, ...(await summary(after)) }
  return { result: JSON.stringify(report, null, 2) }
}

export function rotate($: Engine, e: Record<string, unknown>) {
  const length = e.length ?? 32
  if (typeof length !== 'number' || !Number.isInteger(length) || length < 16 || length > 128) {
    return { deny: 'length must be an integer from 16 to 128' }
  }
  return writeKey($, e, { kind: 'random', length })
}

export function setFromFile($: Engine, e: Record<string, unknown>) {
  const file = e.file
  if (typeof file !== 'string' || !file.startsWith('/')) return { deny: 'file must be an absolute path' }
  return writeKey($, e, { kind: 'file', path: file })
}

// Answers file names only: the values travel to grep on stdin.
export async function leakCheck($: Engine, e: Record<string, unknown>) {
  if (known.size === 0) return { result: 'nothing to look for: this load has not minted or read a value yet' }
  const given = e.paths
  const paths =
    Array.isArray(given) && given.length > 0 && given.every(p => typeof p === 'string' && p.startsWith('/'))
      ? (given as string[])
      : [`${await $.env.get('HOME')}/.claude`]
  const ran = await $.process.run(['grep', '-rlsF', '-f', '-', '--', ...paths], {
    stdin: `${[...known].join('\n')}\n`,
    timeoutMs: 120_000,
  })
  if (ran.exitCode > 1 && ran.stdout === '') return { deny: `grep failed with exit code ${ran.exitCode}` }
  const files = ran.stdout.split('\n').filter(Boolean)
  return { result: JSON.stringify({ searched: paths, valuesLookedFor: known.size, filesHoldingOne: files, partial: ran.exitCode > 1 }, null, 2) }
}

const DATA_OUTPUT = /^(yaml|json|jsonpath|go-template|template|custom-columns)/

function outputFormat(call: Call): string | undefined {
  for (let i = 0; i < call.args.length; i++) {
    const a = call.args[i]!
    if (a === '-o' || a === '--output') return call.args[i + 1]
    if (a.startsWith('--output=')) return a.slice('--output='.length)
    if (a.startsWith('-o')) return a.slice(2).replace(/^=/, '')
  }
  return undefined
}

// Why a call would print Secret data, if it would. Best effort: the real
// wall is a kube identity without `get secrets`.
export function readsSecret(call: Call): string | undefined {
  const p = positionals(call)
  if (call.tool === 'helm') {
    return p[0] === 'get' && ['all', 'manifest', 'values'].includes(p[1] ?? '') ? 'it would print rendered Secrets or chart values' : undefined
  }
  if (call.tool !== 'kubectl') return undefined
  const namesSecret = (p[1] ?? '').split(',').some(r => /^secrets?(\/.*)?$/.test(r))
  if (p[0] === 'get' && namesSecret && DATA_OUTPUT.test(outputFormat(call) ?? '')) return 'it would print Secret data'
  if (call.args.includes('--raw') && call.args.some(a => a.includes('/secrets'))) return 'it would print Secret data through the raw API'
  if (p[0] === 'edit' && namesSecret) return 'it would open Secret data in an editor'
  if (p[0] === 'exec' && /(^|\s)(env|printenv)(\s|$)|\/environ\b/.test(call.text)) {
    return "it would print a container's environment, which Secrets feed"
  }
  return undefined
}

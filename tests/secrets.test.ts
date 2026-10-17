import { expect, mock, test } from 'claude-code/testing'
import { engine, exited, refused } from './helpers'

const ROTATE = 'mcp__infra-guard__secret_rotate'
const SET = 'mcp__infra-guard__secret_set'

test('refuses kubectl and helm commands that print Secret data', async ($, on) => {
  const { ran } = engine(on)
  for (const command of [
    'kubectl get secret app -o yaml',
    'kubectl --context prod get secrets -ojson',
    "ssh pi 'sudo -n k3s kubectl -n popo get secret/popofinder -o jsonpath={.data}'",
    'kubectl get --raw /api/v1/namespaces/popo/secrets/popofinder',
    'kubectl exec deploy/api -- printenv',
    'helm get manifest api -n popo',
  ]) {
    const r = await $.tool.call({ tool: 'Bash', command })
    expect(refused(r)).toContain('refused')
  }
  expect(ran.length).toBe(0)
})

test('lets read-only and explicitly targeted commands through', async ($, on) => {
  const { ran } = engine(on)
  for (const command of [
    'kubectl get pods -o yaml',
    'kubectl get secrets',
    'kubectl describe secret app',
    'kubectl --context k3d-ksg-spike -n spike rollout restart deploy/app',
    'helm upgrade --install api ./chart --kube-context staging',
  ]) {
    const r = await $.tool.call({ tool: 'Bash', command })
    expect(refused(r)).toBeUndefined()
  }
  expect(ran.length).toBe(5)
})

test('refuses a direct cluster change that leaves the kube context ambient', async ($, on) => {
  const { ran, audit } = engine(on)
  on('process.run', () => exited(0, 'prod-cluster\n'))
  const r = await $.tool.call({ tool: 'Bash', command: 'helm upgrade api ./chart -f values-sre.yaml' })
  expect(refused(r)).toContain('ambient kube-context: prod-cluster')
  expect(ran.length).toBe(0)
  expect(audit().at(-1)?.outcome).toBe('refused')
})

test('rotates without returning the value, then withholds output that carries it', async ($, on) => {
  let stored: Record<string, string> = { OTHER: btoa('unrelated-value-1234') }
  let written = ''
  const echoed: string[] = []
  engine(on, { answer: 'Rotate', bash: () => echoed.join('\n') })
  on('process.run', ($, e) => {
    const verb = e.argv[5]
    if (verb === 'get') return exited(0, JSON.stringify({ type: 'Opaque', data: stored }))
    if (verb === 'replace') {
      written = e.init?.stdin ?? ''
      stored = (JSON.parse(written) as { data: Record<string, string> }).data
      return exited(0, 'secret/app replaced')
    }
    return exited(1, '', 'unexpected')
  })

  const r = await $.tool.call({ tool: ROTATE, context: 'k3d-ksg-spike', namespace: 'spike', secret: 'app', key: 'TOKEN' })
  expect(refused(r)).toBeUndefined()
  const minted = (JSON.parse(written) as { data: { TOKEN: string } }).data.TOKEN
  const report = String(r.result)
  expect(report).toContain('"verified": true')
  expect(report.includes(minted)).toBe(false)
  expect(report.includes(atob(minted))).toBe(false)

  echoed.push(`TOKEN=${atob(minted)}`)
  const leak = await $.tool.call({ tool: 'Bash', command: 'cat .env' })
  expect(refused(leak)).toContain('withheld')
})

test('a typed value reaches kubectl alone, and stored rows carrying it are scrubbed', async ($, on) => {
  const typed = 'vendor-token-7c1e9a40'
  let stored: Record<string, string> = {}
  let written = ''
  engine(on, { answer: typed })
  on('process.run', ($, e) => {
    if (e.argv.includes(typed)) throw new Error('the value reached argv')
    const verb = e.argv[5]
    if (verb === 'get') return exited(0, JSON.stringify({ type: 'Opaque', data: stored }))
    if (verb === 'replace') {
      written = e.init?.stdin ?? ''
      stored = (JSON.parse(written) as { data: Record<string, string> }).data
      return exited(0, 'secret/app replaced')
    }
    return exited(1, '', 'unexpected')
  })
  const rows = mock.session(on)

  const r = await $.tool.call({ tool: SET, context: 'k3d-ksg-spike', namespace: 'spike', secret: 'app', key: 'VENDOR' })
  expect(refused(r)).toBeUndefined()
  expect(atob((JSON.parse(written) as { data: { VENDOR: string } }).data.VENDOR)).toBe(typed)
  expect(String(r.result).includes(typed)).toBe(false)

  // A prompt row the person typed, raised as the engine raises one.
  await $.session.append({
    door: 'prompt',
    origin: { kind: 'composer' },
    uuid: crypto.randomUUID(),
    message: { type: 'user', role: 'user', content: [{ type: 'text', text: `pasted: ${typed}` }] },
  })
  const last = rows.appended().at(-1)
  expect(JSON.stringify(last?.message.content)).not.toContain(typed)
  expect(JSON.stringify(last?.message.content)).toContain('redacted')
})

test('a typed answer that is one of the dialog options writes nothing', async ($, on) => {
  let written = false
  engine(on, { answer: 'Cancel' })
  on('process.run', ($, e) => {
    if (e.argv[5] === 'replace') written = true
    return exited(0, JSON.stringify({ type: 'Opaque', data: {} }))
  })
  const r = await $.tool.call({ tool: SET, context: 'k3d-ksg-spike', namespace: 'spike', secret: 'app', key: 'VENDOR' })
  expect(refused(r)).toContain('did not enter a value')
  expect(written).toBe(false)
})

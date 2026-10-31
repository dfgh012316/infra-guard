import type { On } from 'claude-code'
import { expect, mock, test } from 'claude-code/testing'
import { leakPatterns, managedBy } from '../hooks/secrets'
import { BAND, engine, exited, PANE, refused } from './helpers'

const ROTATE = 'mcp__infra-guard__secret_rotate'
const SET = 'mcp__infra-guard__secret_set'

test('refuses commands that print Secret data', async ($, on) => {
  const { ran } = engine(on)
  for (const command of [
    'kubectl get secret app -o yaml',
    'kubectl --context prod get secrets -ojson',
    "ssh pi 'sudo -n k3s kubectl -n popo get secret/popofinder -o jsonpath={.data}'",
    'kubectl get --raw /api/v1/namespaces/popo/secrets/popofinder',
    'kubectl exec deploy/api -- printenv',
    'helm get manifest api -n popo',
    "kubectl --context dev get secret app --template '{{.data.password}}'",
    "kubectl --context dev exec deploy/api -- sh -c 'echo $DB_PASSWORD'",
    'kubectl --context dev exec api-0 -- cat /etc/secrets/token',
    'gcloud secrets versions access latest --secret=telegram',
    'aws secretsmanager get-secret-value --secret-id app',
    'aws ssm get-parameter --name /app/db --with-decryption',
  ]) {
    const r = await $.tool.call({ tool: 'Bash', command })
    expect(refused(r)).toContain('refused')
  }
  expect(ran.length).toBe(0)
})

test('lets read-only and explicitly targeted commands through', async ($, on) => {
  const { ran } = engine(on)
  const commands = [
    'kubectl get pods -o yaml',
    'kubectl get secrets',
    'kubectl describe secret app',
    'kubectl --context k3d-ksg-spike -n spike rollout restart deploy/app',
    'helm upgrade --install api ./chart --kube-context staging',
    'kubectl --context dev exec deploy/api -- ls /tmp',
    'gcloud secrets versions list --secret=telegram',
    'grep -rnE "kubectl patch secret|helm get values" docs/',
  ]
  for (const command of commands) {
    const r = await $.tool.call({ tool: 'Bash', command })
    expect(refused(r)).toBeUndefined()
  }
  expect(ran.length).toBe(commands.length)
})

test('lets helm get through where the person turned it on', { options: { allowHelmGet: true } }, async ($, on) => {
  const { ran } = engine(on)
  const r = await $.tool.call({ tool: 'Bash', command: 'helm get values api -n popo --kube-context dev' })
  expect(refused(r)).toBeUndefined()
  expect(ran.length).toBe(1)
})

test('refuses kubectl exec that leaves the kube context ambient', async ($, on) => {
  const { ran } = engine(on)
  on('process.run', () => exited(0, 'prod-cluster\n'))
  const r = await $.tool.call({ tool: 'Bash', command: 'kubectl exec deploy/api -- rm -rf /data' })
  expect(refused(r)).toContain('ambient kube-context: prod-cluster')
  expect(ran.length).toBe(0)
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

test('logs a rotation, and keeps known values out of logged commands', async ($, on) => {
  let stored: Record<string, string> = {}
  let written = ''
  const { audit } = engine(on, { answer: 'Rotate' })
  on('process.run', ($, e) => {
    const verb = e.argv[5]
    if (verb === 'get') return exited(0, JSON.stringify({ type: 'Opaque', data: stored }))
    if (verb === 'replace') {
      written = e.init?.stdin ?? ''
      stored = (JSON.parse(written) as { data: Record<string, string> }).data
      return exited(0, 'secret/app replaced')
    }
    return exited(0, 'dev\n')
  })
  await $.tool.call({ tool: ROTATE, context: 'k3d-ksg-spike', namespace: 'spike', secret: 'app', key: 'TOKEN' })
  expect(audit().at(-1)?.command).toBe('secret_rotate spike/app key TOKEN on context k3d-ksg-spike')
  expect(audit().at(-1)?.outcome).toBe('ok')

  const value = atob((JSON.parse(written) as { data: { TOKEN: string } }).data.TOKEN)
  await $.tool.call({ tool: 'Bash', command: `kubectl --context k3d-ksg-spike -n spike annotate deploy/app copied=${value}` })
  expect(audit().at(-1)?.command.includes(value)).toBe(false)
})

test('withholds output carrying a multi-line value', async ($, on) => {
  const typed = 'line-one-abcdefgh\nline-two-ijklmnop'
  let stored: Record<string, string> = {}
  engine(on, { answer: 'Set', files: { '/home/u/cert.pem': `${typed}\n` }, bash: () => `cert:\n${typed}\n` })
  on('process.run', ($, e) => {
    if (e.argv[5] === 'get') return exited(0, JSON.stringify({ type: 'Opaque', data: stored }))
    if (e.argv[5] === 'replace') {
      stored = (JSON.parse(e.init?.stdin ?? '{}') as { data: Record<string, string> }).data
      return exited(0, 'secret/app replaced')
    }
    return exited(1, '', 'unexpected')
  })
  await $.tool.call({ tool: SET, context: 'k3d-ksg-spike', namespace: 'spike', secret: 'app', key: 'CERT', file: '/home/u/cert.pem' })
  expect(atob(stored.CERT ?? '')).toBe(typed)
  const r = await $.tool.call({ tool: 'Bash', command: 'cat cert.pem' })
  expect(refused(r)).toContain('withheld')
})

test('refuses to write a Secret that a controller writes back', async ($, on) => {
  let replaced = false
  engine(on, { answer: 'Rotate' })
  const owned = {
    type: 'Opaque',
    data: {},
    metadata: { ownerReferences: [{ kind: 'ExternalSecret', name: 'app', controller: true }] },
  }
  on('process.run', ($, e) => {
    if (e.argv[5] === 'replace') replaced = true
    return exited(0, JSON.stringify(owned))
  })
  const r = await $.tool.call({ tool: ROTATE, context: 'k3d-ksg-spike', namespace: 'spike', secret: 'app', key: 'TOKEN' })
  expect(refused(r)).toContain('managed by ExternalSecret app')
  expect(replaced).toBe(false)
  expect(managedBy({ metadata: { annotations: { 'reconcile.external-secrets.io/data-hash': 'x' } } })).toBe('External Secrets')
  expect(managedBy({ metadata: { ownerReferences: [{ kind: 'Deployment', name: 'app' }] } })).toBeUndefined()
})

test('looks for a PEM line by line, never for an empty or armor line', () => {
  const pem = '-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIU\nshort\n-----END CERTIFICATE-----\n'
  expect(leakPatterns([pem])).toEqual(['MIIBszCCAVmgAwIBAgIU'])
})

test('a value from a file reaches kubectl alone, and stored rows carrying it are scrubbed', async ($, on) => {
  const typed = 'vendor-token-7c1e9a40'
  let stored: Record<string, string> = {}
  let written = ''
  const { asked } = engine(on, { answer: 'Set', files: { '/home/u/vendor.txt': `${typed}\n` } })
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

  const r = await $.tool.call({ tool: SET, context: 'k3d-ksg-spike', namespace: 'spike', secret: 'app', key: 'VENDOR', file: '/home/u/vendor.txt' })
  expect(refused(r)).toBeUndefined()
  expect(atob((JSON.parse(written) as { data: { VENDOR: string } }).data.VENDOR)).toBe(typed)
  expect(String(r.result).includes(typed)).toBe(false)
  // Dialog text and answers can leave the machine (Remote Control): the value is in neither.
  expect(asked.length).toBe(1)
  expect(asked[0]).toContain('21 characters')
  expect(asked[0]!.includes(typed)).toBe(false)

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

test('a cancelled set writes nothing, yet output carrying the file value is withheld', async ($, on) => {
  const value = 'vendor-token-5d20b8e1'
  let written = false
  engine(on, { answer: 'Cancel', files: { '/home/u/vendor.txt': value }, bash: () => `VENDOR=${value}` })
  on('process.run', ($, e) => {
    if (e.argv[5] === 'replace') written = true
    return exited(0, JSON.stringify({ type: 'Opaque', data: {} }))
  })
  const r = await $.tool.call({ tool: SET, context: 'k3d-ksg-spike', namespace: 'spike', secret: 'app', key: 'VENDOR', file: '/home/u/vendor.txt' })
  expect(refused(r)).toContain('did not confirm')
  expect(written).toBe(false)
  const leak = await $.tool.call({ tool: 'Bash', command: 'cat /home/u/vendor.txt' })
  expect(refused(leak)).toContain('withheld')
})

test('secret_set needs an absolute path to a readable, non-empty file', async ($, on) => {
  const { asked } = engine(on, { answer: 'Set', files: { '/home/u/empty.txt': '\n' } })
  on('process.run', () => exited(0, JSON.stringify({ type: 'Opaque', data: {} })))
  const target = { tool: SET, context: 'k3d-ksg-spike', namespace: 'spike', secret: 'app', key: 'VENDOR' } as const
  expect(refused(await $.tool.call({ ...target, file: 'vendor.txt' }))).toContain('absolute path')
  expect(refused(await $.tool.call({ ...target, file: '/home/u/missing.txt' }))).toContain('could not read')
  expect(refused(await $.tool.call({ ...target, file: '/home/u/empty.txt' }))).toContain('holds no value')
  expect(asked.length).toBe(0)
})

// The paste field: a pane where one is placed, else the band above the prompt.
const TARGET = { tool: SET, context: 'k3d-ksg-spike', namespace: 'spike', secret: 'app', key: 'VENDOR' } as const

// A cluster of one Secret, the pane's placement, and what reaches Claude.
function pasting(on: On, { placed }: { placed: boolean }) {
  const state = { placed: placed as boolean | 'no-surface', stored: {} as Record<string, string>, written: '', closed: [] as string[], told: [] as string[] }
  on('process.run', ($, e) => {
    const verb = e.argv[5]
    if (verb === 'get') return exited(0, JSON.stringify({ type: 'Opaque', data: state.stored }))
    if (verb === 'replace') {
      state.written = e.init?.stdin ?? ''
      state.stored = (JSON.parse(state.written) as { data: Record<string, string> }).data
      return exited(0, 'secret/app replaced')
    }
    return exited(1, '', 'unexpected')
  })
  on('ui.open', () => ({
    value: state.placed === true ? { isPlaced: true } : { isPlaced: false, reason: state.placed === false ? 'unasked, 100 columns' : 'no-surface: a -p run' },
  }))
  on('ui.close', ($, e) => {
    state.closed.push(e.id)
    return { value: undefined }
  })
  on('prompt.submit', ($, e) => {
    state.told.push(e.text)
    return { text: e.text }
  })
  return state
}

test('secret_set opens a pane to paste into, writes the value, and tells Claude without it', async ($, on) => {
  const value = 'pasted-token-3f9a0c71'
  const { asked } = engine(on, { bash: () => `VENDOR=${value}` })
  const s = pasting(on, { placed: true })

  const r = await $.tool.call(TARGET)
  expect(refused(r)).toBeUndefined()
  expect(String(r.result)).toContain('in a pane')
  expect(s.written).toBe('')

  const ui = await $.ui.mount({ plugin: 'infra-guard', surface: 'terminal', component: 'Pane', requestId: 'secret-paste', props: PANE })
  await ui.input({ key: 'secret-value', text: `${value}\n` })
  expect(atob((JSON.parse(s.written) as { data: { VENDOR: string } }).data.VENDOR)).toBe(value)
  expect(s.closed).toContain('secret-paste')
  expect(s.told.length).toBe(1)
  expect(s.told[0]).toContain('"verified": true')
  expect(s.told[0]!.includes(value)).toBe(false)
  expect(asked.length).toBe(0)

  const leak = await $.tool.call({ tool: 'Bash', command: 'cat .env' })
  expect(refused(leak)).toContain('withheld')
})

test('where no pane is placed the band holds the field, and Cancel writes nothing', async ($, on) => {
  engine(on)
  const s = pasting(on, { placed: false })
  const r = await $.tool.call(TARGET)
  expect(String(r.result)).toContain('above the prompt')

  const ui = await $.ui.mount({ plugin: 'infra-guard', surface: 'terminal', component: 'AbovePrompt', props: BAND })
  expect(await ui.find({ key: 'secret-value' })).toBeDefined()
  await ui.press({ key: 'secret-cancel' })
  expect(s.written).toBe('')
  expect(s.told).toEqual(['infra-guard: the person cancelled secret_set for VENDOR'])
  await ui.redraw(BAND)
  expect(await ui.find({ key: 'secret-value' })).toBeUndefined()
})

test('an empty Enter keeps the field; one paste waits at a time', async ($, on) => {
  engine(on)
  const s = pasting(on, { placed: true })
  await $.tool.call(TARGET)
  expect(refused(await $.tool.call({ ...TARGET, key: 'OTHER' }))).toContain('already waiting')

  const ui = await $.ui.mount({ plugin: 'infra-guard', surface: 'terminal', component: 'Pane', requestId: 'secret-paste', props: PANE })
  await ui.input({ key: 'secret-value', text: '\n' })
  expect(s.told.length).toBe(0)
  await ui.input({ key: 'secret-value', text: 'pasted-token-0b7d22e9' })
  expect(s.told.length).toBe(1)
})

test('with no screen to paste into, secret_set leaves nothing waiting', async ($, on) => {
  engine(on)
  const s = pasting(on, { placed: true })
  s.placed = 'no-surface'
  expect(refused(await $.tool.call(TARGET))).toContain('pass `file`')
  expect(s.told.length).toBe(0)
  s.placed = true
  expect(refused(await $.tool.call(TARGET))).toBeUndefined()
})

test('a paste is logged when it ends, without the value', async ($, on) => {
  const value = 'pasted-token-9e4c1a57'
  const { audit } = engine(on)
  pasting(on, { placed: true })
  await $.tool.call(TARGET)
  expect(audit().length).toBe(0)
  const ui = await $.ui.mount({ plugin: 'infra-guard', surface: 'terminal', component: 'Pane', requestId: 'secret-paste', props: PANE })
  await ui.input({ key: 'secret-value', text: value })
  expect(audit().at(-1)?.command).toBe('secret_set spike/app key VENDOR on context k3d-ksg-spike')
  expect(audit().at(-1)?.outcome).toBe('ok')
  expect(JSON.stringify(audit()).includes(value)).toBe(false)
})

test('no field opens for a Secret a controller writes back', async ($, on) => {
  const { audit } = engine(on)
  let opened = 0
  on('process.run', () =>
    exited(0, JSON.stringify({ type: 'Opaque', data: {}, metadata: { annotations: { 'reconcile.external-secrets.io/data-hash': 'x' } } })),
  )
  on('ui.open', () => {
    opened++
    return { value: { isPlaced: true } }
  })
  expect(refused(await $.tool.call(TARGET))).toContain('managed by External Secrets')
  expect(opened).toBe(0)
  expect(audit().at(-1)?.outcome).toBe('refused')
})

test('drops a background task notification carrying a known value, and tells Claude one was', async ($, on) => {
  let written = ''
  const { clock } = engine(on, { answer: 'Rotate' })
  on('process.run', ($, e) => {
    if (e.argv[5] === 'get') return exited(0, JSON.stringify({ type: 'Opaque', data: written ? (JSON.parse(written) as { data: Record<string, string> }).data : {} }))
    if (e.argv[5] === 'replace') {
      written = e.init?.stdin ?? ''
      return exited(0, 'secret/app replaced')
    }
    return exited(1, '', 'unexpected')
  })
  const told: string[] = []
  on('prompt.submit', ($, e) => {
    told.push(e.text)
    return { text: e.text }
  })
  await $.tool.call({ tool: ROTATE, context: 'k3d-ksg-spike', namespace: 'spike', secret: 'app', key: 'TOKEN' })
  const minted = atob((JSON.parse(written) as { data: { TOKEN: string } }).data.TOKEN)
  const notification = { origin: { kind: 'task-notification' }, wait: false } as const

  const leaked = await $.prompt.submit({ ...notification, text: `<task-notification>TOKEN=${minted}</task-notification>` })
  expect(leaked.drop).toContain('withheld')
  const ordinary = await $.prompt.submit({ ...notification, text: '<task-notification>pods ready</task-notification>' })
  expect(ordinary.drop).toBeUndefined()
  await clock.settle()
  expect(told.some(t => t.includes(minted))).toBe(false)
  expect(told.some(t => t.includes('notification carried a Secret value'))).toBe(true)
})

test('says so in the band when stored rows pass it by, and asks Claude to offer leak_check after a write', async ($, on) => {
  let stored: Record<string, string> = {}
  engine(on, { answer: 'Rotate' })
  on('process.run', ($, e) => {
    if (e.argv[5] === 'get') return exited(0, JSON.stringify({ type: 'Opaque', data: stored }))
    if (e.argv[5] === 'replace') {
      stored = (JSON.parse(e.init?.stdin ?? '{}') as { data: Record<string, string> }).data
      return exited(0, 'secret/app replaced')
    }
    return exited(1, '', 'unexpected')
  })
  on('prompt.submit', ($, e) => ({ text: e.text }))
  await $.tool.call({ tool: 'Bash', command: 'ls' })
  const ui = await $.ui.mount({ plugin: 'infra-guard', surface: 'terminal', component: 'AbovePrompt', props: BAND })
  expect(await ui.find({ text: /transcript scrub is off/ })).toBeUndefined()
  await $.prompt.submit({ text: 'next', origin: { kind: 'composer' }, wait: false })
  await ui.redraw(BAND)
  expect(await ui.find({ text: /transcript scrub is off/ })).toBeDefined()

  const r = await $.tool.call({ tool: ROTATE, context: 'k3d-ksg-spike', namespace: 'spike', secret: 'app', key: 'TOKEN' })
  expect(refused(r)).toBeUndefined()
  expect(r.context?.join(' ')).toContain('leak_check')
})

test('says nothing while the result rows come by', async ($, on) => {
  engine(on)
  on('prompt.submit', ($, e) => ({ text: e.text }))
  await $.tool.call({ tool: 'Bash', command: 'ls' })
  // The tool's result row, raised as the engine stores it; with a plugin above
  // that sends rows on past infra-guard, none comes by.
  await $.session.append({
    door: 'tool-result',
    origin: { kind: 'tool', tool: 'Bash' },
    uuid: crypto.randomUUID(),
    message: { type: 'user', role: 'user', content: [{ type: 'tool_result', tool_use_id: 'toolu_1', content: 'ok' }] },
  })
  await $.prompt.submit({ text: 'next', origin: { kind: 'composer' }, wait: false })
  const ui = await $.ui.mount({ plugin: 'infra-guard', surface: 'terminal', component: 'AbovePrompt', props: BAND })
  expect(await ui.find({ text: /transcript scrub is off/ })).toBeUndefined()
})


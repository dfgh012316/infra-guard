import { describe, expect, test } from 'claude-code/testing'
import type { AuditEntry } from '../types'
import { settle } from '../hooks/approval'
import { mask, timeline } from '../hooks/audit'
import { scanScript } from '../hooks/script'
import { calls, isWrite, namesTarget, scripts, switchesTarget } from '../hooks/shell'
import { ghActiveUser, iniValue } from '../hooks/targets'
import { summarizePlan, terraformRuns } from '../hooks/terraform'
import { ghRunProgress, rolloutProgress } from '../hooks/watch'
import { engine, exited, HOME, refused } from './helpers'

describe('reading command lines', () => {
  test('finds infra calls behind sudo, k3s, env and inside ssh quotes', () => {
    const found = calls("cd infra && sudo -n k3s kubectl -n popo rollout restart deploy/app; ssh pi 'helm upgrade api ./c' | tee log", '/w', HOME)
    expect(found.map(c => [c.tool, c.cwd])).toEqual([
      ['kubectl', '/w/infra'],
      ['helm', '/w/infra'],
    ])
    expect(found.every(isWrite)).toBe(true)
    expect(found.some(namesTarget)).toBe(false)
  })

  test('tells reads from writes and named targets from ambient ones', () => {
    const one = (line: string) => calls(line, '/w', HOME)[0]!
    expect(isWrite(one('kubectl get pods -o yaml'))).toBe(false)
    expect(isWrite(one('kubectl rollout status deploy/app'))).toBe(false)
    expect(isWrite(one('gcloud compute instances delete vm-1'))).toBe(true)
    expect(isWrite(one('aws s3 sync ./out s3://bucket'))).toBe(true)
    expect(namesTarget(one('helm upgrade api ./c --kube-context prod'))).toBe(true)
    expect(namesTarget(one('kubectl --context dev apply -f x.yaml'))).toBe(true)
    expect(namesTarget(one('KUBECONFIG=/k kubectl --kubeconfig /k apply -f x.yaml'))).toBe(false)
    expect(switchesTarget(one('kubectl config use-context prod'))).toBe(true)
    expect(switchesTarget(one('gcloud config set project example-sre'))).toBe(true)
    expect(switchesTarget(one('gh auth switch'))).toBe(true)
  })

  test('reads no commands out of heredoc bodies, and keeps here-strings and quoted <<', () => {
    const line = [
      "cat > up.sh <<'EOF'",
      'helm upgrade --install api ./c',
      'EOF',
      'cat <<-END > x',
      '\tkubectl delete ns prod',
      '\tEND',
      'kubectl apply -f - <<< "$manifest"',
      'echo "a << b" && helm upgrade api ./c',
    ].join('\n')
    expect(calls(line, '/w', HOME).map(c => `${c.tool} ${c.args[0]}`)).toEqual(['kubectl apply', 'helm upgrade'])
  })

  test('finds the scripts a line runs, from the directory it runs them in', () => {
    expect(scripts('cd charts && ./scripts/upgrade.sh api sre && bash ~/bin/x.sh', '/w', HOME)).toEqual([
      '/w/charts/scripts/upgrade.sh',
      '/home/u/bin/x.sh',
    ])
  })
})

describe('reading scripts', () => {
  test('flags an upgrade.sh that runs helm on the ambient context', () => {
    const text = [
      '#!/usr/bin/env bash',
      'set -euo pipefail',
      'chart=$1 env=$2',
      '# picks only the values file; the target is whatever context is current',
      'helm upgrade --install "$chart" "./charts/$chart" \\',
      '  -f "values-$env.yaml"',
      'kubectl get pods',
      'kubectl --context "$CTX" rollout restart deploy/api',
      'kubectl config use-context prod',
      'terraform -chdir=infra apply -auto-approve',
      './post.sh',
    ].join('\n')
    const { findings, nested } = scanScript('/w/scripts/upgrade.sh', text, HOME)
    expect(findings.map(f => [f.line, f.why])).toEqual([
      [5, 'ambient'],
      [9, 'switches'],
      [10, 'terraform'],
    ])
    expect(nested).toEqual(['/w/scripts/post.sh'])
  })
})

describe('terraform', () => {
  test('reads the folder and plan of each apply or destroy', () => {
    expect(terraformRuns('cd tf && terraform -chdir=prod apply tfplan && terraform destroy', '/w', HOME)).toEqual([
      { verb: 'apply', dir: '/w/tf/prod', plan: 'tfplan', isDestroy: false },
      { verb: 'destroy', dir: '/w/tf', isDestroy: true },
    ])
    expect(terraformRuns('terraform apply -auto-approve -var env=prod', '/w', HOME)[0]?.plan).toBeUndefined()
  })

  test('counts what a plan creates, changes, replaces and destroys', () => {
    const plan = {
      resource_changes: [
        { address: 'a.one', change: { actions: ['create'] } },
        { address: 'a.two', change: { actions: ['update'] } },
        { address: 'a.three', change: { actions: ['delete', 'create'] } },
        { address: 'a.four', change: { actions: ['delete'] } },
        { address: 'a.five', change: { actions: ['no-op'] } },
      ],
    }
    expect(summarizePlan(plan)).toEqual({ create: ['a.one'], update: ['a.two'], replace: ['a.three'], delete: ['a.four'] })
  })
})

describe('approval', () => {
  test('turns only an ask for a call the person approved into an allow', () => {
    const approved = new Set(['toolu_1'])
    expect(settle({ decision: 'ask' }, 'toolu_1', approved).decision).toBe('allow')
    expect(settle({ decision: 'ask' }, 'toolu_2', approved).decision).toBe('ask')
    expect(settle({ decision: 'ask' }, undefined, approved).decision).toBe('ask')
    expect(settle({ decision: 'deny', reason: 'Bash(terraform:*)' }, 'toolu_1', approved)).toEqual({ decision: 'deny', reason: 'Bash(terraform:*)' })
    expect(settle({ decision: 'allow' }, 'toolu_1', approved).decision).toBe('allow')
    // The hook tells an allow it made from the verdict beneath by identity.
    const beneath = { decision: 'ask' as const, reason: 'the mode asks' }
    expect(settle(beneath, 'toolu_2', approved)).toBe(beneath)
  })

  test('leaves the verdict beneath a Bash check that names no call', async ($, on) => {
    on('tool.check', () => ({ decision: 'ask', reason: 'the mode asks' }))
    const verdict = await $.tool.check({ tool: 'Bash', input: { command: './scripts/upgrade.sh api sre' } })
    expect(verdict.decision).toBe('ask')
  })
})

describe('targets, audit and watches', () => {
  test('reads gcloud ini and the active gh account', () => {
    expect(iniValue('[core]\naccount = a@b.c\nproject = example-sre\n', 'core', 'project')).toBe('example-sre')
    const hosts = 'github.com:\n    git_protocol: https\n    users:\n        alice:\n        bob:\n    user: bob\nghe.corp:\n    user: carol\n'
    expect(ghActiveUser(hosts)).toBe('bob')
  })

  test('masks secret values and draws the newest change first', () => {
    expect(mask('kubectl create secret generic s --from-literal=TOKEN=abc123 DB_PASSWORD=hunter2')).toBe(
      'kubectl create secret generic s --from-literal=TOKEN=*** DB_PASSWORD=***',
    )
    const entry = (at: string, command: string): AuditEntry => ({ at, session: 's', cwd: '/w', command, targets: { kube: 'dev' }, outcome: 'ok', ms: 5 })
    const table = timeline([entry('2026-10-17T01:00:00.000Z', 'helm upgrade a'), entry('2026-10-17T02:00:00.000Z', 'kubectl apply | x')], 10)
    const rows = table.split('\n').slice(2)
    expect(rows[0]).toContain('02:00:00')
    expect(rows[0]).toContain('kubectl apply \\| x')
  })

  test('reads rollout and workflow run states', () => {
    expect(rolloutProgress({ exitCode: 0, stdout: 'Waiting for deployment "app" rollout to finish: 1 of 2 updated replicas are available...\n', stderr: '' })).toEqual({
      state: 'running',
      status: '1 of 2 updated replicas are available...',
    })
    expect(rolloutProgress({ exitCode: 0, stdout: 'deployment "app" successfully rolled out\n', stderr: '' }).state).toBe('done')
    expect(rolloutProgress({ exitCode: 1, stdout: '', stderr: 'error: deployment "app" exceeded its progress deadline' }).state).toBe('failed')
    expect(ghRunProgress({ exitCode: 0, stdout: '{"status":"completed","conclusion":"failure"}', stderr: '' })).toEqual({ state: 'failed', status: 'failure' })
  })
})

describe('the Bash hook', () => {
  test('refuses terraform apply without a saved plan, and logs the refusal', async ($, on) => {
    const { ran, audit } = engine(on)
    on('process.run', () => exited(0, 'dev-cluster\n'))
    const r = await $.tool.call({ tool: 'Bash', command: 'terraform apply -auto-approve' })
    expect(refused(r)).toContain('without a saved plan')
    expect(ran.length).toBe(0)
    expect(audit().at(-1)?.outcome).toBe('refused')
  })

  test('applies a saved plan once the person approves its destroys', async ($, on) => {
    const { ran, audit } = engine(on, { answer: 'Apply, destroying 1' })
    const plan = { resource_changes: [{ address: 'x.a', change: { actions: ['create'] } }, { address: 'x.b', change: { actions: ['delete'] } }] }
    on('process.run', ($, e) => (e.argv[1] === 'show' ? exited(0, JSON.stringify(plan)) : exited(0, 'dev-cluster\n')))
    const r = await $.tool.call({ tool: 'Bash', command: 'terraform apply tfplan' })
    expect(refused(r)).toBeUndefined()
    expect(ran).toEqual(['terraform apply tfplan'])
    expect(audit().at(-1)?.outcome).toBe('confirmed')
    expect(audit().at(-1)?.note).toContain('1 to add')
  })

  test('stops a script that runs helm on the ambient context unless the person runs it', async ($, on) => {
    const script = 'helm upgrade --install "$1" ./charts/$1 -f values-$2.yaml\n'
    const { ran } = engine(on, { files: { '/w/scripts/upgrade.sh': script } })
    on('process.run', () => exited(0, 'prod-cluster\n'))
    const r = await $.tool.call({ tool: 'Bash', command: './scripts/upgrade.sh api sre' })
    expect(refused(r)).toContain('upgrade.sh:1')
    expect(ran.length).toBe(0)
  })

  test('tells Claude the targets the first time an infra command runs, then only on a change', async ($, on) => {
    engine(on)
    on('process.run', () => exited(0, 'dev-cluster\n'))
    const first = await $.tool.call({ tool: 'Bash', command: 'kubectl get pods' })
    const second = await $.tool.call({ tool: 'Bash', command: 'kubectl get pods' })
    expect(first.context?.join(' ')).toContain('kube dev-cluster')
    expect(second.context).toBeUndefined()
  })

  test('lets a heredoc that writes a deploy script through', async ($, on) => {
    const { ran } = engine(on)
    on('process.run', () => exited(0, 'prod-cluster\n'))
    const command = "cat > up.sh <<'EOF'\nhelm upgrade --install api ./charts/api\nEOF"
    const r = await $.tool.call({ tool: 'Bash', command })
    expect(refused(r)).toBeUndefined()
    expect(ran).toEqual([command])
  })
})

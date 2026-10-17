import { mock } from 'claude-code/testing'
import type { On } from 'claude-code'
import type { AuditEntry } from '../types'

export const HOME = '/home/u'

export function exited(exitCode: number, stdout: string, stderr = '') {
  return { value: { exitCode, stdout, stderr, isStdoutTruncated: false, isStderrTruncated: false } }
}

export function refused(r: { deny?: string; isError?: true; text?: string }): string | undefined {
  return r.deny ?? (r.isError ? r.text : undefined)
}

type Options = { files?: Record<string, string>; answer?: string; bash?: () => string }

// Stands in for the engine around the mod: cwd, env, store, clock, files, the
// person's answer to every dialog, and Bash itself. A test adds process.run.
export function engine(on: On, { files = {}, answer = 'Cancel', bash = () => 'ok' }: Options = {}) {
  const store = new Map<string, unknown>()
  on('store.get', ($, e) => ({ value: store.get(e.key) }))
  on('store.set', ($, e) => {
    store.set(e.key, e.value)
    return { value: undefined }
  })
  mock.clock(on)
  mock.env(on, { HOME })
  on('session.cwd', () => ({ value: '/w' }))
  on('session.id', () => ({ value: 'session-1' }))
  on('fs.read', ($, e) => (e.path in files ? { value: files[e.path]! } : { deny: 'missing' }))
  on('tool.call', { tool: 'AskUserQuestion' }, ($, e) => ({
    result: { questions: e.questions, answers: { [e.questions[0]!.question]: answer } },
  }))
  const ran: string[] = []
  on('tool.call', { tool: 'Bash' }, ($, e) => {
    ran.push(e.command)
    return { result: { stdout: bash(), stderr: '', interrupted: false } }
  })
  return { ran, audit: () => (store.get('audit') as AuditEntry[] | undefined) ?? [] }
}

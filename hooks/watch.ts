// Reading one poll of a watched operation. Each watch is a read-only command
// the mod builds itself, so a watch cannot run anything the model chose.

export type Progress = { state: 'running' | 'done' | 'failed'; status: string }
type Ran = { exitCode: number; stdout: string; stderr: string }

export function rolloutProgress(r: Ran): Progress {
  const last = `${r.stdout}\n${r.stderr}`.trim().split('\n').at(-1) ?? ''
  if (r.exitCode !== 0) return { state: 'failed', status: last || `exit code ${r.exitCode}` }
  if (r.stdout.includes('successfully rolled out')) return { state: 'done', status: 'successfully rolled out' }
  return { state: 'running', status: last.replace(/^Waiting for deployment "[^"]*" rollout to finish: /, '') || 'waiting' }
}

export function ghRunProgress(r: Ran): Progress {
  if (r.exitCode !== 0) return { state: 'failed', status: r.stderr.trim().split('\n').at(-1) ?? `exit code ${r.exitCode}` }
  const run = JSON.parse(r.stdout) as { status?: string; conclusion?: string }
  if (run.status !== 'completed') return { state: 'running', status: run.status ?? 'unknown' }
  return run.conclusion === 'success' ? { state: 'done', status: 'success' } : { state: 'failed', status: run.conclusion ?? 'unknown' }
}

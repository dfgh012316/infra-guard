export type Targets = { kube?: string; gcloud?: string; gh?: string; aws?: string }

export type AuditEntry = {
  at: string
  session: string
  cwd: string
  command: string
  targets: Targets | null
  outcome: 'ok' | 'error' | 'refused' | 'confirmed'
  note?: string
  ms: number
}

export type Watch = {
  id: string
  kind: 'rollout' | 'gh-run'
  label: string
  argv: string[]
  startedAt: number
  deadline: number
  status: string
  state: 'running' | 'done' | 'failed' | 'timeout' | 'stopped'
  endedAt?: number
}

// A Secret value waiting to be pasted: what the field says, never the value.
// `inPane`: the pane holds the field; otherwise the band above the prompt does.
export type PendingPaste = { label: string; inPane: boolean }

declare module 'claude-code' {
  interface PluginState {
    'infra-guard': { targets: Targets | null; watches: Watch[]; pending: PendingPaste | null }
  }
}

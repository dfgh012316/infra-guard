export type Targets = { kube?: string; gcloud?: string; gh?: string; aws?: string; argocd?: string }

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

// A script run waiting for the person's review, as the review pane draws it.
export type ReviewScript = { path: string; lines: string[]; flagged: { line: number; why: string }[]; more: number }
export type PendingReview = {
  command: string
  cwd: string
  ambient: string
  production: string[]
  scripts: ReviewScript[]
  unread: string[]
  // The pane holds the review; otherwise the band offers to open it.
  inPane: boolean
}

declare module 'claude-code' {
  interface PluginState {
    'infra-guard': { targets: Targets | null; watches: Watch[]; pending: PendingPaste | null; scrubSkipped: boolean; review: PendingReview | null }
  }
}

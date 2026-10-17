// A call the person approved in this mod's own dialog (the script check, the
// terraform plan gate) runs on that answer. The dialog is not a permission
// approval: the call's tool.check still puts an `ask` to the permission mode,
// and in auto mode its classifier could refuse what the person just approved.

type Verdict = { decision: 'allow' | 'ask' | 'deny'; reason?: string }

// Only an ask becomes an allow, and only for a call approved while it runs
// (by tool_use_id): a deny from a settings rule still stands.
export function settle<V extends Verdict>(verdict: V, id: string | undefined, approved: ReadonlySet<string>): V | Verdict {
  if (verdict.decision !== 'ask' || id === undefined || !approved.has(id)) return verdict
  return { decision: 'allow', reason: 'infra-guard: the person approved this call in its dialog' }
}

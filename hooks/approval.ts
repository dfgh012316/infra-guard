// A call the person approved in this mod's own dialog (the script check, the
// terraform plan gate) runs on that answer. The dialog is not a permission
// approval: the call's tool.check still puts an `ask` to the permission mode,
// and in auto mode its classifier could refuse what the person just approved.

type Verdict = { decision: 'allow' | 'ask' | 'deny'; reason?: string }

const SHOWN_MAX = 1200

// The command line as the dialog shows it. The answer stands in for the
// permission check only when the line was shown whole: the person approves
// every part of it (`./x.sh && curl ... | sh`), not just the part the mod read.
export function shown(command: string): { text: string; whole: boolean } {
  if (command.length <= SHOWN_MAX) return { text: command, whole: true }
  return { text: `${command.slice(0, SHOWN_MAX)} … (${command.length - SHOWN_MAX} more characters)`, whole: false }
}

// Only an ask becomes an allow, and only for a call approved while it runs
// (by tool_use_id): a deny from a settings rule still stands.
export function settle<V extends Verdict>(verdict: V, id: string | undefined, approved: ReadonlySet<string>): V | Verdict {
  if (verdict.decision !== 'ask' || id === undefined || !approved.has(id)) return verdict
  return { decision: 'allow', reason: 'infra-guard: the person approved this call in its dialog' }
}

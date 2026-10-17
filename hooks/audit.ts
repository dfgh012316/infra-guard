import type { AuditEntry, Targets } from '../types'

// Values after these never reach the log: a best effort by spelling.
const SECRET_FLAG = /(--from-literal=[^=\s]+=|--(?:password|token|secret|client-secret)[= ])(\S+)/gi
const SECRET_ASSIGNMENT = /\b([A-Za-z0-9_]*(?:PASSWORD|TOKEN|SECRET|APIKEY|API_KEY)[A-Za-z0-9_]*=)(\S+)/gi

export function mask(command: string): string {
  return command.replace(SECRET_FLAG, '$1***').replace(SECRET_ASSIGNMENT, '$1***').slice(0, 400)
}

export function targetLine(t: Targets | null): string {
  if (t === null) return 'unknown'
  const parts = [
    t.kube && `kube ${t.kube}`,
    t.gcloud && `gcloud ${t.gcloud}`,
    t.gh && `gh ${t.gh}`,
    t.aws && `aws ${t.aws}`,
  ].filter(Boolean)
  return parts.length > 0 ? parts.join(' · ') : 'none set'
}

function cell(text: string): string {
  return text.replace(/\|/g, '\\|').replace(/\n/g, ' ')
}

// Newest first, as a markdown table.
export function timeline(entries: readonly AuditEntry[], limit: number): string {
  if (entries.length === 0) return 'No infrastructure changes recorded yet.'
  const rows = entries
    .slice(-limit)
    .reverse()
    .map(
      e =>
        `| ${e.at.replace('T', ' ').slice(0, 19)} | ${e.outcome}${e.note ? `: ${cell(e.note)}` : ''} | ${cell(targetLine(e.targets))} | \`${cell(e.command)}\` |`,
    )
  return ['| time (UTC) | outcome | targets at the time | command |', '| --- | --- | --- | --- |', ...rows].join('\n')
}

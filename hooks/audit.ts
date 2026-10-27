import type { AuditEntry, Targets } from '../types'

// Values after these never reach the log: a best effort by spelling. The Bash
// hook also replaces every value the mod has minted or read (secrets.ts).
const SECRET_FLAG = /(--from-literal[= ][^=\s]+=|--(?:password|token|secret|client-secret|auth-token)[= ])(\S+)/gi
const SECRET_ASSIGNMENT = /\b([A-Za-z0-9_]*(?:PASSWORD|PASSWD|TOKEN|SECRET|APIKEY|API_KEY|PRIVATE_KEY|CREDENTIALS?|DSN)[A-Za-z0-9_]*=)(\S+)/gi
// scheme://user:password@host
const URL_CREDENTIALS = /([a-z][a-z0-9+.-]*:\/\/[^\s:/@'"]+:)([^\s@'"]+)(@)/gi
// A Secret's data in a patch or manifest given inline: `{"data":{...}}`.
const INLINE_DATA = /("?(?:data|stringData)"?\s*:\s*)\{[^{}]*\}/g
// A value echoed into a command that writes a Secret: `echo -n v | kubectl create secret ...`.
const PIPED_VALUE = /\b((?:echo(?:\s+-[neE]+)*|printf(?:\s+'%s'|\s+"%s")?)\s+)('[^']*'|"[^"]*"|[^\s|]+)(?=\s*\|)/g

export function mask(command: string): string {
  const piped = /secret/i.test(command) ? command.replace(PIPED_VALUE, '$1***') : command
  return piped
    .replace(URL_CREDENTIALS, '$1***$3')
    .replace(INLINE_DATA, '$1{***}')
    .replace(SECRET_FLAG, '$1***')
    .replace(SECRET_ASSIGNMENT, '$1***')
    .slice(0, 400)
}

export function targetLine(t: Targets | null): string {
  if (t === null) return 'unknown'
  const parts = [
    t.kube && `kube ${t.kube}`,
    t.gcloud && `gcloud ${t.gcloud}`,
    t.gh && `gh ${t.gh}`,
    t.aws && `aws ${t.aws}`,
    t.argocd && `argocd ${t.argocd}`,
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

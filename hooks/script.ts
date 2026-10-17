import { calls, isWrite, namesTarget, scripts, switchesTarget, withoutHeredocs } from './shell'

// What a script would run against the ambient target, line by line, and the
// scripts it runs in turn (resolved from its own folder: a best guess, as a
// script may `cd` or build the path from $0).

export type Finding = { file: string; line: number; text: string; why: 'ambient' | 'switches' | 'terraform' }

export function scanScript(file: string, text: string, home: string): { findings: Finding[]; nested: string[] } {
  const dir = file.slice(0, file.lastIndexOf('/')) || '/'
  const findings: Finding[] = []
  const nested: string[] = []
  const lines = withoutHeredocs(text).split('\n')
  for (let i = 0; i < lines.length; i++) {
    const start = i
    let line = lines[i]!
    while (line.endsWith('\\') && i + 1 < lines.length) line = `${line.slice(0, -1)} ${lines[++i]!}`
    for (const call of calls(line, dir, home)) {
      const why =
        call.tool === 'terraform' && isWrite(call)
          ? 'terraform'
          : switchesTarget(call)
            ? 'switches'
            : isWrite(call) && !namesTarget(call)
              ? 'ambient'
              : undefined
      if (why !== undefined) findings.push({ file, line: start + 1, text: call.text.slice(0, 160), why })
    }
    nested.push(...scripts(line, dir, home))
  }
  return { findings, nested }
}

const WHY = {
  ambient: 'no explicit target',
  switches: 'switches the ambient target',
  terraform: 'terraform change the plan gate cannot see inside a script',
}

export function describeFindings(findings: Finding[], home: string): string[] {
  return findings.slice(0, 6).map(f => `${f.file.replace(home, '~')}:${f.line}  ${f.text}  (${WHY[f.why]})`)
}

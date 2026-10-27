import { calls, isWrite, namesTarget, scriptRuns, steps, switchesTarget, withoutHeredocs, type ScriptRun } from './shell'

// What a script would run against the ambient target, line by line, and the
// scripts it runs in turn. Relative paths resolve from the directory the
// script runs in, as bash resolves them: the caller's, then each `cd` the
// script makes; `$(dirname "$0")` is read as the script's own folder.

export type Finding = { file: string; line: number; text: string; why: 'ambient' | 'switches' | 'terraform' }

const OWN_DIR = /\$\(\s*dirname\s+"?\$(?:0|\{0\}|\{?BASH_SOURCE(?:\[0\])?\}?)"?\s*\)/g

export function scanScript(file: string, text: string, home: string, cwd: string): { findings: Finding[]; nested: ScriptRun[] } {
  const own = file.slice(0, file.lastIndexOf('/')) || '/'
  const findings: Finding[] = []
  const nested: ScriptRun[] = []
  const lines = withoutHeredocs(text).replace(OWN_DIR, own).split('\n')
  let dir = cwd
  for (let i = 0; i < lines.length; i++) {
    const start = i
    let line = lines[i]!
    while (line.endsWith('\\') && i + 1 < lines.length) line = `${line.slice(0, -1)} ${lines[++i]!}`
    for (const call of calls(line, dir, home)) {
      const why =
        (call.tool === 'terraform' || call.tool === 'terragrunt') && isWrite(call)
          ? 'terraform'
          : switchesTarget(call)
            ? 'switches'
            : isWrite(call) && !namesTarget(call)
              ? 'ambient'
              : undefined
      if (why !== undefined) findings.push({ file, line: start + 1, text: call.text.slice(0, 160), why })
    }
    nested.push(...scriptRuns(line, dir, home))
    // A `cd` outside a subshell holds for the lines after it.
    dir = steps(line, dir, home).at(-1)?.cwd ?? dir
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

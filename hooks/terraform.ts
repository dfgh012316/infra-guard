import { calls, isTerraform, join, terraformWords, type Call } from './shell'

export type TerraformRun = { tool: 'terraform' | 'tofu' | 'terragrunt'; verb: 'apply' | 'destroy'; dir: string; plan?: string; isDestroy: boolean; isAll: boolean }
export type PlanSummary = { create: string[]; update: string[]; replace: string[]; delete: string[] }

function flagValue(c: Call, ...names: string[]): string | undefined {
  for (let i = 0; i < c.args.length; i++) {
    const a = c.args[i]!
    for (const n of names) {
      if (a === n) return c.args[i + 1]
      if (a.startsWith(`${n}=`)) return a.slice(n.length + 1)
    }
  }
  return undefined
}

// `terraform [-chdir=d] apply [plan]`, `terraform destroy` and terragrunt's
// own spellings, with the folder each runs in (the plan path is read from
// there, as terraform does). `isAll`: terragrunt across every module below.
export function terraformRuns(line: string, cwd: string, home: string): TerraformRun[] {
  return calls(line, cwd, home)
    .filter(isTerraform)
    .flatMap((c): TerraformRun[] => {
      const p = terraformWords(c)
      const chdir = flagValue(c, '-chdir', '--terragrunt-working-dir', '--working-dir')
      const dir = chdir === undefined ? c.cwd : join(c.cwd, chdir)
      const isAll = c.tool === 'terragrunt' && (c.args[0] === 'run-all' || c.args.includes('--all') || c.args.includes('--terragrunt-include-dir') || c.args.includes('--queue-include-dir'))
      if (p[0] === 'apply') return [{ tool: c.tool, verb: 'apply', dir, plan: p[1], isDestroy: c.args.includes('-destroy'), isAll }]
      if (p[0] === 'destroy') return [{ tool: c.tool, verb: 'destroy', dir, isDestroy: true, isAll }]
      return []
    })
}

type PlanJson = { resource_changes?: { address: string; change: { actions: string[] } }[] }

export function summarizePlan(plan: unknown): PlanSummary {
  const s: PlanSummary = { create: [], update: [], replace: [], delete: [] }
  for (const rc of (plan as PlanJson).resource_changes ?? []) {
    const a = rc.change.actions.join(',')
    if (a === 'create') s.create.push(rc.address)
    else if (a === 'update') s.update.push(rc.address)
    else if (a === 'delete') s.delete.push(rc.address)
    else if (a === 'delete,create' || a === 'create,delete') s.replace.push(rc.address)
  }
  return s
}

export function describePlan(s: PlanSummary): string {
  return `${s.create.length} to add, ${s.update.length} to change, ${s.replace.length} to replace, ${s.delete.length} to destroy`
}

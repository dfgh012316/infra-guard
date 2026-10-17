import { calls, join, positionals } from './shell'

export type TerraformRun = { verb: 'apply' | 'destroy'; dir: string; plan?: string; isDestroy: boolean }
export type PlanSummary = { create: string[]; update: string[]; replace: string[]; delete: string[] }

// `terraform [-chdir=d] apply [plan]` and `terraform destroy`, with the folder
// terraform runs in (the plan path is read from there, as terraform does).
export function terraformRuns(line: string, cwd: string, home: string): TerraformRun[] {
  return calls(line, cwd, home)
    .filter(c => c.tool === 'terraform')
    .flatMap((c): TerraformRun[] => {
      const p = positionals(c)
      const chdir = c.args.find(a => a.startsWith('-chdir='))?.slice('-chdir='.length)
      const dir = chdir === undefined ? c.cwd : join(c.cwd, chdir)
      if (p[0] === 'apply') return [{ verb: 'apply', dir, plan: p[1], isDestroy: c.args.includes('-destroy') }]
      if (p[0] === 'destroy') return [{ verb: 'destroy', dir, isDestroy: true }]
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

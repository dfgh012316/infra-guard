# infra-guard

Guardrails for infrastructure work in [Claude Code](https://code.claude.com). It shows which cluster, project and account Claude is pointed at, makes cluster changes name their target, reads scripts before they run, gates `terraform apply` on a plan a person approved, and lets Claude rotate Kubernetes Secrets without ever seeing the values.

It is a Claude Code **mod**: a plugin with a hooks module that runs inside Claude Code, so the checks run on every tool call instead of depending on Claude remembering a rule in `CLAUDE.md`.

> Status: early (0.x). Tested on the Linux CLI (WSL2) with Claude Code 2.1.301–2.1.302, and on the macOS CLI with 2.1.302 against GKE (all but `secret_rotate` and `secret_set`). The VS Code extension is untested.

## Why

A deploy script took `upgrade.sh <chart> <env>`. The `<env>` argument only picked `values-<env>.yaml`; the cluster was whatever kube-context happened to be current, and the script neither printed nor accepted one. Run while the context pointed at another environment, it applied one environment's values to the other's release.

Reading that script before running it was not enough: it was read to see how it built the helm command, not to see what it silently inherited. infra-guard reads it for that, every time.

## What it does

| Guard | Behavior |
| --- | --- |
| Ambient targets | A line above the prompt shows the current kube context, gcloud project (and configuration), gh account and AWS profile. Names matching `prodPattern` show in red with `PROD`. Claude is told the targets with the first infra command and again whenever they change. |
| Named targets | A `kubectl` or `helm` command that changes a cluster must pass `--context` / `--kube-context` (or `HELM_KUBECONTEXT`); otherwise it is refused, with the ambient context in the reason. |
| Script check | Before `./x.sh`, `bash x.sh` or `source x.sh` runs, the mod reads the script (and scripts it runs, two levels down) and lists every line that would act on the ambient target, switch it, or run terraform. The person decides; on a production target the button reads "Run against production". A script it cannot read is asked about too. |
| Terraform plan gate | `terraform apply` runs only from a saved plan. The mod reads `terraform show -json` itself, counts what the plan adds, changes, replaces and destroys, lists the destroyed addresses, and asks. `terraform destroy` asks with the number of resources in state. The plan contents are not passed to Claude. |
| Approval | A script or plan the person approved in one of these dialogs runs on that answer: the mod allows that one call at the permission check, so the permission mode (in auto mode, its classifier) does not ask about it again. Only an ask becomes an allow; a settings rule that denies the command still refuses it. Each such allow is said in a dim transcript line and in the call's audit note. |
| Audit | Every infra change, refusal and script run is logged with the targets at the time and its outcome. `/timeline [count]` prints them newest first. Values after `--from-literal=`, `--password`, `*_TOKEN=` and similar are masked before they are stored. |
| Watches | `watch_start` hands a Deployment rollout or a GitHub Actions run to the mod, which polls it read-only every 5 seconds and sends Claude a message when it ends, so Claude does not sleep-loop. The mod builds each watch command itself; Claude cannot pass an arbitrary one. |
| Secret values | `secret_rotate` and `secret_set` write one key of an existing Secret after the person confirms; the value goes to `kubectl` on stdin and Claude gets key names, sizes and fingerprints. Commands that would print Secret data (`get secret -o yaml/json/jsonpath/…`, `--raw …/secrets`, `edit secret`, `exec … env`, `helm get values/manifest/all`) are refused. Any tool output carrying a value the mod minted or read, plain or base64, is withheld, and stored conversation rows carrying one are scrubbed. |

### Tools Claude gets

| Tool | Does |
| --- | --- |
| `mcp__infra-guard__secret_rotate` | Sets a key to a new random value (16–128 characters) after confirmation, then reads it back to verify. |
| `mcp__infra-guard__secret_set` | Same, with a value the person types into the dialog (for a token a vendor issued). |
| `mcp__infra-guard__secret_keys` | Lists keys with byte sizes and session-scoped fingerprints; warns when `last-applied-configuration` holds a plaintext copy. |
| `mcp__infra-guard__leak_check` | Searches files (default `~/.claude`) for every value the mod has seen this session and answers file names only. |
| `mcp__infra-guard__watch_start` / `watch_stop` | Start or stop a rollout or GitHub Actions watch. |

## Install

```sh
claude plugin marketplace add dfgh012316/infra-guard
claude plugin install infra-guard@jerrytech
```

Or from inside a session: `/plugin install infra-guard --marketplace dfgh012316/infra-guard`.

Requires a Claude Code release with mods. Auto-update is off by default for third-party marketplaces: run `claude plugin update infra-guard@jerrytech`, or turn on auto-update for the `jerrytech` marketplace under `/plugin` → Marketplaces.

To try it for one session without installing: `claude --plugin-dir /path/to/infra-guard`.

## Configuration

| Option | Default | Meaning |
| --- | --- | --- |
| `prodPattern` | `prod\|prd\|production` | Case-insensitive regular expression. A target name that matches is shown and confirmed as production. |

Set it in `/config`, or under `pluginConfigs` in `settings.json`.

## What it is not

infra-guard catches mistakes. It does not stop someone, or a model, determined to get around it.

- **It reads command lines; it is not a shell.** No variable expansion, aliases or functions. Makefile targets, paths built from `$(dirname "$0")` or variables, and deploy tools written in Python or Go are invisible to the script check. Commands outside its lists (for example kubectl plugins) are not treated as writes.
- **The real wall is permissions.** Give the kube identity Claude uses no `get secrets` and no production write access, and keep a privileged kubeconfig for the secret tools (they take an absolute `kubeconfig` path). The command-line guards only protect against slips.
- **Known Secret values live in memory, for the current load only.** A reload or restart forgets them, and a value the mod never minted or read is not caught. Values shorter than 8 characters are not tracked. Multi-line values (PEM), wrapped or URL-safe base64, and partial prints can slip through.
- **`kubectl apply` leaves old values behind.** A Secret created with `kubectl apply` keeps a plaintext copy in the `kubectl.kubernetes.io/last-applied-configuration` annotation. `secret_keys` warns about it; the mod does not remove it.
- **A typed value is visible while typing.** The dialog has no masked input; the value goes under "Other". It is not written to the transcript or history.
- **The audit log is local.** Plaintext JSON under `~/.claude/plugins/store/`, last 1000 entries, shared by sessions on the machine, not atomic and not tamper-proof. It records only commands Claude ran.
- **Failures.** If the Bash check throws, the command is refused; if the output check throws, the output is withheld. Claude Code skips a hook whose own error handler fails, so this is not a guarantee.
- **Mods are not sandboxed.** This one runs `kubectl`, `terraform`, `gh` and `grep` as you, and reads gcloud, gh and AWS config files. It makes no network requests of its own. Run `claude plugin validate .` to list every hook and API it uses.

Desktop app WSL sessions do not load plugins, so the guards do not run there.

## Development

```sh
claude plugin validate --strict .   # manifest, hooks, and the APIs the mod calls
claude plugin test .                 # unit tests, run by Claude Code's engine
```

TypeScript types for the mod API are generated into `.claude-plugin/types/` when Claude Code loads the mod (for example `claude --plugin-dir .`); after that, `tsc -p .` type-checks the hooks and tests. Load it again after adding a tool so the generated tool names include it.

Engine behavior worth knowing:

- `$.ui.ask` reaches the person in every permission mode (it is the `AskUserQuestion` tool), but the answer is not a permission approval: the call's `tool.check` still puts an `ask` to the mode's decider, in auto mode its classifier. The mod answers `allow` at `tool.check` for the one call it asked about, by `tool_use_id`.
- `$.process.run` hands the child its stdin as a socket, so `--patch-file /dev/stdin` and `grep -f /dev/stdin` fail with `ENXIO`. Use forms that stream fd 0 (`-f -`).
- Claude Code stores an allowed tool result's raw stdout separately in the transcript (`toolUseResult`), out of reach of `session.append`. Output has to be withheld in `tool.call`, before it is stored.
- The runtime has `crypto.subtle.digest` but no HMAC; fingerprints use a random per-load salt with SHA-256, so they compare values within one session only.

## License

[Apache-2.0](LICENSE)

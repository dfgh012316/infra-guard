# infra-guard

[![test](https://github.com/dfgh012316/infra-guard/actions/workflows/test.yml/badge.svg)](https://github.com/dfgh012316/infra-guard/actions/workflows/test.yml)

Guardrails for infrastructure work in [Claude Code](https://code.claude.com). It shows which cluster, project and account Claude is pointed at, makes cluster changes name their target, reads scripts before they run, gates `terraform apply` on a plan a person approved, and lets Claude rotate Kubernetes Secrets without ever seeing the values.

It is a Claude Code **mod**: a plugin with a hooks module that runs inside Claude Code, so the checks run on every tool call instead of depending on Claude remembering a rule in `CLAUDE.md`.

> Status: 1.0 (see [Versioning](#versioning)). The unit tests run on every push and daily against the newest Claude Code release (CI above). Each release is also run through the in-session checks in [docs/verification.md](docs/verification.md), which records the runs: 1.0.0 passed them all on the Linux CLI (WSL2) with Claude Code 2.1.316. The guards through 0.5 were also tested on the macOS CLI with 2.1.302 against GKE (all but `secret_rotate` and `secret_set`). In the VS Code extension Claude Code draws nothing a mod draws, so there is no band and the script check asks in a dialog (untested). If you do not see the target line above the prompt in a terminal, the guards are not running.

## Why

A deploy script took `upgrade.sh <chart> <env>`. The `<env>` argument only picked `values-<env>.yaml`; the cluster was whatever kube-context happened to be current, and the script neither printed nor accepted one. Run while the context pointed at another environment, it applied one environment's values to the other's release.

Reading that script before running it was not enough: it was read to see how it built the helm command, not to see what it silently inherited. infra-guard reads it for that, every time.

## What it does

| Guard | Behavior |
| --- | --- |
| Ambient targets | A line above the prompt shows the current kube context, gcloud project (and configuration), gh account, AWS profile and argocd context. Names matching `prodPattern` show in red with `PROD`. Claude is told the targets with the first infra command and again whenever they change. |
| Named targets | A `kubectl` (or `kubecolor`), `helm`, `helmfile` or `argocd` command that changes a cluster must pass `--context` / `--kube-context` (or `HELM_KUBECONTEXT`) / `--argocd-context` (or `--server`, `ARGOCD_SERVER`); otherwise it is refused, with the ambient context in the reason. helmfile's `--kube-context` outranks a `kubeContext` under `helmDefaults` or an environment, so the reason asks for the context the helmfile names, if it names one. `kubectl exec`, `cp` and `debug` count as changes. Commands are found inside loops and conditionals, behind `sudo`, `env`, `timeout`, `xargs` and `watch`, and inside quoted text a shell or `ssh` runs or a `$(...)` substitutes; other quoted text (a grep pattern, a commit message) is data. The command a `Monitor` runs gets every check a Bash command does. |
| Script check | Before `./x.sh`, `bash x.sh` or `source x.sh` runs, the mod reads the script (and scripts it runs, two levels down) and lists every line that would act on the ambient target, switch it (`kubectx`, `kubens`, `kubectl config use-context`, …), or run terraform, OpenTofu or terragrunt. Relative paths resolve as bash resolves them: from the caller's directory, following each `cd`, with `$(dirname "$0")` read as the script's folder. The person decides in a review pane: every script whole, with line numbers and its flagged lines listed in its heading, each flagged line marked with why, above it the command line and the ambient targets. The pane asks for the rows the whole review takes (the layout may give fewer); the arrows scroll, `r` runs it ("Run against production" on a production target), `c` or Esc cancels. A script it cannot read is listed there too. The call is refused while the person reads, and Claude is told to run it again once they decide; that run goes through only unchanged (the same command line, directory, ambient targets and script texts) and only once. Where no pane is placed unasked (a terminal under 144 columns), a row above the prompt opens it (ctrl+x tab, then Review); with no surface at all (VS Code, `-p`), a dialog lists the flagged lines instead. A reload of the mod closes a waiting review (or paste field) and tells Claude that nothing ran. |
| Terraform plan gate | `terraform apply`, `tofu apply` and `terragrunt apply` run only from a saved plan. The mod reads `show -json` itself, counts what the plan adds, changes, replaces and destroys, lists the destroyed addresses, and asks. `destroy` asks with the number of resources in state. `terragrunt run-all apply` / `destroy` (and `--all`) is refused, as there is no one plan to show. The plan contents are not passed to Claude. |
| Approval | The review and every dialog show the whole command line. A script the person approved in the review, or a plan approved in its dialog, runs on that answer: the mod allows that one call at the permission check, so the permission mode (in auto mode, its classifier) does not ask about it again. Only an ask becomes an allow; a settings rule that denies the command still refuses it; a line too long to show whole (over 1200 characters) is left to the permission check. Each such allow is said in a dim transcript line and in the call's audit note. |
| Audit | Every infra change, refusal, script run and `secret_rotate` / `secret_set` write is logged with the targets at the time and its outcome. `/timeline [count]` prints them newest first. Before a command is stored, every Secret value the mod has minted or read is replaced, and values after `--from-literal`, `--password`, `*_TOKEN=` and similar, URL credentials (`://user:pass@`), inline `{"data": {...}}` and values echoed into a command that writes a Secret are masked. |
| Watches | `watch_start` hands a Deployment rollout or a GitHub Actions run to the mod, which polls it read-only every 5 seconds and sends Claude a message when it ends, so Claude does not sleep-loop. The mod builds each watch command itself; Claude cannot pass an arbitrary one. |
| Secret values | `secret_rotate` mints a value; `secret_set` takes one the person pastes into the mod's own field, or reads one from a file they wrote; either writes one key of an existing Secret after the person confirms, the value goes to `kubectl` on stdin and Claude gets key names, sizes and fingerprints. A Secret a controller writes back (an ExternalSecret, a SealedSecret, External Secrets' merge mode) is refused: change it at its source. Commands that would print Secret data (`get secret -o yaml/json/jsonpath/…` or `--template`, `--raw …/secrets`, `edit secret`, `exec` that prints the environment, a credential variable or a secret file, `gcloud secrets versions access`, `aws secretsmanager get-secret-value`, `aws ssm get-parameter --with-decryption`, and `helm get values/manifest/all` unless `allowHelmGet` is on) are refused. Any tool output carrying a value the mod minted or read, plain or base64, multi-line included, is withheld; a background task's notification carrying one (a `Monitor` event, a background command's result) is dropped, and Claude is told that one was; stored conversation rows carrying one are scrubbed. |

### Tools Claude gets

| Tool | Does |
| --- | --- |
| `mcp__infra-guard__secret_rotate` | Sets a key to a new random value (16–128 characters) after confirmation, then reads it back to verify. |
| `mcp__infra-guard__secret_set` | Same, with a value the person supplies (a token a vendor issued). By default the mod opens a field to paste it into: a pane that takes the keys at once, or, where no pane is placed, a field above the prompt that ctrl+x tab reaches. It returns at once, and Claude gets a message when the value is set or cancelled (Cancel, or Esc in the pane). With `file`, it reads a file the person wrote instead (an absolute path; one trailing newline is dropped) and asks to confirm with its length and fingerprint. |
| `mcp__infra-guard__secret_keys` | Lists keys with byte sizes and session-scoped fingerprints; warns when `last-applied-configuration` holds a plaintext copy. |
| `mcp__infra-guard__leak_check` | Searches files for every value the mod has seen this session and answers file names only. By default it searches `~/.claude` and Claude Code's temp folder (`$CLAUDE_CODE_TMPDIR`, else the system's, then `claude-<uid>`), where a `Monitor`'s or background command's raw output lands. |
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
| `prodPattern` | `prod\|prd\|production` | Case-insensitive regular expression. A target name that matches is shown and confirmed as production. Add the names that do not say so: a GCP project id, the cluster that runs production's Argo CD, the Argo CD host. |
| `allowHelmGet` | `false` | Let `helm get values`, `helm get manifest` and `helm get all` run. Turn it on where chart values hold no credentials; a Secret a chart renders still prints with the manifest. |

Set it in `/config`, or under `pluginConfigs` in `settings.json`.

## What it is not

infra-guard catches mistakes. It does not stop someone, or a model, determined to get around it.

- **It reads command lines; it is not a shell.** No variable expansion, aliases or functions. Makefile targets, paths built from variables (`"$DIR/x.sh"`), and deploy tools written in Python or Go are invisible to the script check. Commands outside its lists (for example kubectl plugins) are not treated as writes.
- **The real wall is permissions.** Give the kube identity Claude uses no `get secrets` and no production write access, and keep a privileged kubeconfig for the secret tools (they take an absolute `kubeconfig` path). The command-line guards only protect against slips.
- **Known Secret values live in memory, for the current load only.** A reload or restart forgets them, and a value the mod never minted or read is not caught. Values shorter than 8 characters are not tracked. Wrapped or URL-safe base64 and partial prints can slip through. `leak_check` looks for a multi-line value (a PEM) line by line, so a file it names holds at least one whole line of a value.
- **Another plugin can step past the transcript scrub.** Hooks nest by tier: plugins an administrator manages run outside the ones a person installs, and one of them may send `session.append` on beneath this mod, so stored rows are not scrubbed (Claude Code says so in the transcript, as `infra-guard: its session.append hook was skipped`). The mod notices once a turn starts after tool calls none of whose result rows reached it: the band then reads `transcript scrub is off`, and a `secret_rotate` or `secret_set` write asks Claude to offer `leak_check`. Output withholding happens in `tool.call` and is not affected by that.
- **Another plugin can step past the approval, too.** The same tiers hold for `tool.check`: when an administrator-managed plugin sends it on beneath this mod (Claude Code says so, as `infra-guard: its tool.check hook was skipped`), a script approved in the review or a plan approved in its dialog gets no allow from the mod at the permission check. The rerun is still matched against what was reviewed, but the permission mode decides it alone: it may ask again, or in auto mode its classifier may refuse it, and no `allowed this command at the permission check` line appears. The notice concerns that one step: the command checks run in `tool.call` and stay on. Claude Code prints it once per load, so it can appear beside a call the mod did allow.
- **`kubectl apply` leaves old values behind.** A Secret created with `kubectl apply` keeps a plaintext copy in the `kubectl.kubernetes.io/last-applied-configuration` annotation. `secret_keys` warns about it; the mod does not remove it.
- **Dialog answers can leave the machine.** In proxy captures of Claude Code 2.1.302 signed in with claude.ai, a value typed into a dialog (under "Other") never reached the model or the local transcript. With [Remote Control](https://code.claude.com/docs/en/remote-control) connected (as `remoteControlAtStartup: true` does for every session), it was sent to Anthropic in the session's event stream (`POST /v1/code/sessions/<id>/worker/events`). With Remote Control off, the session sent no `/v1/code/sessions` requests, and the value was in none of its 44 requests. Remote Control is one setting away for every session, so `secret_set` never takes a value through a dialog, and the mod's dialogs carry only key names, lengths and fingerprints. In the same kind of capture, with Remote Control connected, a value pasted into the mod's own field (0.5.0) appeared in none of the 208 requests the session sent, nor in any of Claude Code's files on disk.
- **The paste field shows what you paste.** It has no masked mode; it closes on Enter. A pane the mod opens on its own is placed from 144 terminal columns; narrower, the field sits above the prompt instead.
- **The value file is yours to guard.** Claude is told only its path. The mod knows the value once it has read the file, so output carrying it is withheld from then on; a read of the file before that is not caught. Write it in your own terminal and delete it when the Secret is set.
- **Claude Code writes some output to disk before the mod sees it.** A `Monitor`'s events and a background command's output go to `tasks/<id>.output` under Claude Code's temp folder, and a result too large to inline to `tool-results/` under `~/.claude/projects/`. Withholding a result or dropping a notification keeps a value from Claude, not off the disk. `leak_check` searches both by default; delete the files it names.
- **The audit log is local.** Plaintext JSON under `~/.claude/plugins/store/`, last 1000 entries, shared by sessions on the machine, not atomic and not tamper-proof. It records commands Claude ran and the secret tools' writes, never a value.
- **Failures.** If the Bash or Monitor check throws before the command runs, a line that names an infra CLI or a script (by spelling alone) is refused, and any other runs with its output still checked; if the output check throws, the output is withheld. Claude Code skips a hook whose own error handler fails, so this is not a guarantee.
- **Mods are not sandboxed.** This one runs `kubectl`, `terraform`, `gh` and `grep` as you, and reads gcloud, gh and AWS config files. It makes no network requests of its own. Run `claude plugin validate .` to list every hook and API it uses.

Desktop app WSL sessions do not load plugins, so the guards do not run there.

## Development

```sh
claude plugin validate --strict .   # manifest, hooks, and the APIs the mod calls
claude plugin test .                 # unit tests, run by Claude Code's engine
```

Neither needs a login. CI ([`.github/workflows/test.yml`](.github/workflows/test.yml)) runs both on each push and pull request, and daily against the newest Claude Code release beside the one the current version was tested on, as a release of Claude Code can change the mod engine under the mod. Before a release, run the in-session checks in [docs/verification.md](docs/verification.md): they cover what the tests' fakes cannot (the pane and the band as drawn, the keys, how Claude takes a refusal, and other plugins' hooks around this one). `verify/setup.sh` lays out the sandbox they run in.

TypeScript types for the mod API are generated into `.claude-plugin/types/` when Claude Code loads the mod (for example `claude --plugin-dir .`); after that, `tsc -p .` type-checks the hooks and tests. Load it again after adding a tool so the generated tool names include it.

Engine behavior worth knowing:

- A `$.ui.ask` answer is not always local: while Remote Control is connected, Claude Code sends it to Anthropic in the session's event stream, though it never enters the model's context. Collect secrets some other way.
- `$.ui.ask` reaches the person in every permission mode (it is the `AskUserQuestion` tool), but the answer is not a permission approval: the call's `tool.check` still puts an `ask` to the mode's decider, in auto mode its classifier. The mod answers `allow` at `tool.check` for the one call it asked about, by `tool_use_id`.
- `$.process.run` hands the child its stdin as a socket, so `--patch-file /dev/stdin` and `grep -f /dev/stdin` fail with `ENXIO`. Use forms that stream fd 0 (`-f -`).
- Claude Code stores an allowed tool result's raw stdout separately in the transcript (`toolUseResult`), out of reach of `session.append`. Output has to be withheld in `tool.call`, before it is stored.
- A function the mod hands `$` to must be declared at the top level of its file; the engine checks this when it loads the module.
- A hook's budget (10 s) counts every wait but one on `next` or a `$` call, so a hook cannot wait for a press in a pane. The script review refuses the call and has Claude run it again once the person decides.
- `$.prompt.submit` from inside a `prompt.submit` hook is refused (it would wait on the turn the hook holds). Submit from `$.clock.after(0, ...)`, a dispatch of its own.
- The runtime has `crypto.subtle.digest` but no HMAC; fingerprints use a random per-load salt with SHA-256, so they compare values within one session only.

## Versioning

From 1.0.0, versions follow [semver](https://semver.org) for what you configure or call: the tools and their inputs, the `prodPattern` and `allowHelmGet` options, and `/timeline`. A minor release may guard more (another CLI, another way to print a Secret), so a command that ran before can be refused after it; a major release renames or removes one of those. Refusal texts, what the band and the panes draw, and the audit file's format can change in any release.

## License

[Apache-2.0](LICENSE)

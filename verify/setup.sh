#!/usr/bin/env bash
# Lays out the sandbox the in-session checks in docs/verification.md run in.
#
#   verify/setup.sh            a kubeconfig whose one context nobody can reach,
#                              and the fixtures
#   verify/setup.sh --cluster  also a throwaway k3d cluster, ig-verify, for the
#                              Secret checks
#
# It never reads or changes your own kubeconfig: what it writes is under $IG
# (default /tmp/ig-verify), k3d is told not to touch the default kubeconfig,
# and every kubectl call names its kubeconfig and context.
set -euo pipefail
IG="${IG:-/tmp/ig-verify}"
here="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$IG/work"

# One context, named so the band shows it as production, pointing at a port
# nothing listens on: a command that slips past the guards fails to connect.
# The user holds a dummy token, as with no credential kubectl asks for a
# username and the command would wait on a prompt instead.
cat > "$IG/kubeconfig" <<'EOF'
apiVersion: v1
kind: Config
clusters:
- name: ig-verify-prod
  cluster:
    server: https://127.0.0.1:9
contexts:
- name: ig-verify-prod
  context:
    cluster: ig-verify-prod
    user: nobody
current-context: ig-verify-prod
users:
- name: nobody
  user:
    token: not-a-token
EOF
cp "$here/up.sh" "$IG/work/up.sh"
: > "$IG/work/events.log"

if [[ "${1:-}" == "--cluster" ]]; then
  k3d cluster create ig-verify --kubeconfig-update-default=false --kubeconfig-switch-context=false --wait
  k3d kubeconfig get ig-verify > "$IG/k3d.yaml"
  kube=(kubectl --kubeconfig "$IG/k3d.yaml" --context k3d-ig-verify)
  "${kube[@]}" create namespace ig-verify
  # A one-character value: too short for the mod to track, so nothing that
  # prints it is withheld before the checks begin.
  "${kube[@]}" --namespace ig-verify create secret generic app --from-literal=TOKEN=x
  # A dummy value for secret_set to write, which the checks then look for.
  printf 'ig-verify-%s' "$(head -c 18 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')" > "$IG/token.txt"
fi

echo "Sandbox ready in $IG. Start the session with:"
echo "  cd $IG/work && KUBECONFIG=$IG/kubeconfig claude --plugin-dir $(dirname "$here")"

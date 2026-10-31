#!/usr/bin/env bash
# infra-guard verification fixture: it exits before anything runs.
# Line 8 runs helm on the ambient kube-context, which the script check flags.
set -euo pipefail
ENV="${2:-dev}"
echo "would upgrade ${1:-api} with values-$ENV.yaml"
exit 0
helm upgrade --install "$1" "./charts/$1" -f "values-$ENV.yaml"

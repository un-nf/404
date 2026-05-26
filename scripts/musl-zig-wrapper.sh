#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: bash ./scripts/musl-zig-wrapper.sh <cc|c++> [compiler args...]

This wrapper normalizes Rust-style --target arguments before invoking Zig with
the canonical musl target expected by the local build flow and GitHub Actions.
EOF
}

if [[ $# -lt 1 ]]; then
  usage >&2
  exit 1
fi

frontend="$1"
shift

case "$frontend" in
  cc|c++)
    ;;
  *)
    echo "unsupported Zig frontend: $frontend" >&2
    usage >&2
    exit 1
    ;;
esac

zig_bin="${ZIG_BIN:-zig}"
musl_target="${MUSL_ZIG_TARGET:-x86_64-linux-musl}"
args=()
skip_target_value=0

for arg in "$@"; do
  if [[ "$skip_target_value" -eq 1 ]]; then
    skip_target_value=0
    continue
  fi

  case "$arg" in
    --target=*|-target=*)
      ;;
    --target|-target)
      skip_target_value=1
      ;;
    *)
      args+=("$arg")
      ;;
  esac
done

exec "$zig_bin" "$frontend" -target "$musl_target" "${args[@]}"
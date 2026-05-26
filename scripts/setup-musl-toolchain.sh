#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: bash ./scripts/setup-musl-toolchain.sh --wrapper-dir PATH [options]

Options:
  --wrapper-dir PATH   Directory to populate with musl-gcc and musl-g++
  --zig-bin PATH       Zig executable or absolute path (default: zig)
  --target VALUE       Zig target triple (default: x86_64-linux-musl)
  --help               Show this help text

The generated wrappers call the shared repo implementation in
scripts/musl-zig-wrapper.sh.
EOF
}

wrapper_dir=""
zig_bin="zig"
target="x86_64-linux-musl"

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --wrapper-dir)
      wrapper_dir="$2"
      shift 2
      ;;
    --zig-bin)
      zig_bin="$2"
      shift 2
      ;;
    --target)
      target="$2"
      shift 2
      ;;
    --help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -z "$wrapper_dir" ]]; then
  echo "--wrapper-dir is required" >&2
  usage >&2
  exit 1
fi

repo_root=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
wrapper_impl="$repo_root/scripts/musl-zig-wrapper.sh"

if [[ ! -f "$wrapper_impl" ]]; then
  echo "missing wrapper implementation: $wrapper_impl" >&2
  exit 1
fi

mkdir -p "$wrapper_dir"

zig_bin_quoted=$(printf '%q' "$zig_bin")
target_quoted=$(printf '%q' "$target")
wrapper_impl_quoted=$(printf '%q' "$wrapper_impl")

for wrapper_name in musl-gcc musl-g++; do
  case "$wrapper_name" in
    musl-gcc)
      frontend="cc"
      ;;
    musl-g++)
      frontend="c++"
      ;;
  esac

  frontend_quoted=$(printf '%q' "$frontend")
  wrapper_path="$wrapper_dir/$wrapper_name"

  cat > "$wrapper_path" <<EOF
#!/usr/bin/env bash
set -euo pipefail
export ZIG_BIN=$zig_bin_quoted
export MUSL_ZIG_TARGET=$target_quoted
exec bash $wrapper_impl_quoted $frontend_quoted "\$@"
EOF

  chmod +x "$wrapper_path"
done

printf '%s\n' "$wrapper_dir"
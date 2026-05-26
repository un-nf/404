#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: bash ./scripts/resolve-zig-cxx-runtime.sh [options]

Options:
  --zig-bin PATH       Zig executable or absolute path (default: zig)
  --target VALUE       Zig target triple (default: x86_64-linux-musl)
  --help               Show this help text

Prints the target-specific Rust flags needed for Rust's normal musl linker path
to locate Zig's libc++, libc++abi, and libunwind archives.
EOF
}

zig_bin="zig"
target="x86_64-linux-musl"

while [[ "$#" -gt 0 ]]; do
  case "$1" in
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

cache_root="${ZIG_GLOBAL_CACHE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/zig}/o"
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

cat > "$tmpdir/probe.cc" <<'EOF'
int main() {
  return 0;
}
EOF

"$zig_bin" c++ -target "$target" "$tmpdir/probe.cc" -o "$tmpdir/probe" >/dev/null 2>&1

latest_archive_dir() {
  local archive_name="$1"
  local latest

  latest=$(find "$cache_root" -type f -name "$archive_name" -printf '%T@ %h\n' | sort -nr | head -n 1 | cut -d' ' -f2-)

  if [[ -z "$latest" ]]; then
    echo "failed to locate $archive_name under $cache_root" >&2
    exit 1
  fi

  printf '%s\n' "$latest"
}

libcxx_dir=$(latest_archive_dir 'libc++.a')
libcxxabi_dir=$(latest_archive_dir 'libc++abi.a')
libunwind_dir=$(latest_archive_dir 'libunwind.a')

printf '%s\n' "-L native=$libcxx_dir -L native=$libcxxabi_dir -L native=$libunwind_dir -C link-arg=-Wl,--start-group -C link-arg=-lc++ -C link-arg=-lc++abi -C link-arg=-lunwind -C link-arg=-Wl,--end-group"
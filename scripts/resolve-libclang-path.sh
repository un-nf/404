#!/usr/bin/env bash
set -euo pipefail

has_libclang_shared_library() {
  local directory="$1"

  [[ -d "$directory" ]] || return 1

  compgen -G "$directory/libclang.so" >/dev/null || \
    compgen -G "$directory/libclang.so.*" >/dev/null || \
    compgen -G "$directory/libclang-*.so" >/dev/null || \
    compgen -G "$directory/libclang-*.so.*" >/dev/null || \
    compgen -G "$directory/libclang.dylib" >/dev/null || \
    compgen -G "$directory/libclang.dll" >/dev/null
}

emit_if_valid() {
  local directory="$1"

  if has_libclang_shared_library "$directory"; then
    printf '%s\n' "$directory"
    exit 0
  fi
}

if [[ -n "${LIBCLANG_PATH:-}" ]]; then
  emit_if_valid "$LIBCLANG_PATH"
fi

if command -v llvm-config >/dev/null 2>&1; then
  emit_if_valid "$(llvm-config --libdir)"
fi

for candidate in \
  /usr/lib/llvm-*/lib \
  /usr/lib64/llvm-*/lib \
  /usr/local/opt/llvm/lib \
  /opt/homebrew/opt/llvm/lib \
  /usr/lib/x86_64-linux-gnu \
  /usr/lib/aarch64-linux-gnu \
  /usr/lib64 \
  /usr/lib \
  /usr/local/lib \
  /usr/local/lib64
do
  for expanded in $candidate; do
    emit_if_valid "$expanded"
  done
done

cat >&2 <<'EOF'
Unable to locate a shared libclang installation.

STATIC uses bindgen through native TLS dependencies, so the host build needs a
shared libclang runtime in addition to the clang compiler binary.

On Debian or Ubuntu, install it with:
  sudo apt-get install -y libclang-dev

If libclang is installed in a nonstandard location, export LIBCLANG_PATH to the
directory containing libclang.so before running cargo.
EOF
exit 1
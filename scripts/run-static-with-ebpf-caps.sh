#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "${SCRIPT_DIR}/.." && pwd)
STATIC_DIR="${REPO_ROOT}/src/STATIC_proxy"
BUILD_MODE=${BUILD_MODE:-debug}
RUN_MODE=${STATIC_EBPF_RUN_MODE:-auto}
RESOLVE_LIBCLANG_SCRIPT="${REPO_ROOT}/scripts/resolve-libclang-path.sh"

case "${BUILD_MODE}" in
    debug)
        CARGO_ARGS=(build)
        BINARY_PATH="${STATIC_DIR}/target/debug/static_proxy"
        ;;
    release)
        CARGO_ARGS=(build --release)
        BINARY_PATH="${STATIC_DIR}/target/release/static_proxy"
        ;;
    *)
        echo "Unsupported BUILD_MODE=${BUILD_MODE}; expected 'debug' or 'release'" >&2
        exit 1
        ;;
esac

case "${RUN_MODE}" in
    auto)
        if [[ -n "${WSL_DISTRO_NAME:-}" ]]; then
            EFFECTIVE_RUN_MODE=sudo
        else
            EFFECTIVE_RUN_MODE=filecaps
        fi
        ;;
    filecaps|sudo)
        EFFECTIVE_RUN_MODE=${RUN_MODE}
        ;;
    *)
        echo "Unsupported STATIC_EBPF_RUN_MODE=${RUN_MODE}; expected 'auto', 'filecaps', or 'sudo'" >&2
        exit 1
        ;;
esac

if ! command -v cargo >/dev/null 2>&1; then
    echo "Missing required command: cargo" >&2
    exit 1
fi

if [[ -z "${LIBCLANG_PATH:-}" ]]; then
    LIBCLANG_PATH=$(bash "${RESOLVE_LIBCLANG_SCRIPT}")
    export LIBCLANG_PATH
fi

cd "${STATIC_DIR}"
cargo "${CARGO_ARGS[@]}"

if [[ "${EFFECTIVE_RUN_MODE}" == "sudo" ]]; then
    exec sudo --preserve-env=HOME,XDG_DATA_HOME,XDG_CONFIG_HOME,RUST_LOG,STATIC_EBPF_MAP_PATH "${BINARY_PATH}" "$@"
fi

if ! command -v setcap >/dev/null 2>&1; then
    echo "Missing required command: setcap" >&2
    echo "Install libcap2-bin, or rerun with STATIC_EBPF_RUN_MODE=sudo." >&2
    exit 1
fi

sudo setcap cap_bpf,cap_net_admin,cap_sys_admin+ep "${BINARY_PATH}"

exec "${BINARY_PATH}" "$@"
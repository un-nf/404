#!/bin/sh
set -eu

usage() {
  cat <<'EOF'
Usage: ./distro/build.sh [options]

Options:
  --static-binary PATH   Path to the linux/musl STATIC binary
  --ttl-object PATH      Path to the compiled ttl_editor.o artifact
  --version VALUE        Version string to write into /opt/404/distro-version
  --output PATH          Output tar.gz path
  --image-tag VALUE      Docker image tag to use for the temporary build image
  --help                 Show this help text
EOF
}

ROOT_DIR=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
DISTRO_DIR="$ROOT_DIR/distro"
DEFAULT_STATIC_BINARY="$ROOT_DIR/src/STATIC_proxy/target/x86_64-unknown-linux-musl/release/static_proxy"
DEFAULT_TTL_OBJECT="$ROOT_DIR/src/ebpf/ttl_editor.o"
DEFAULT_OUTPUT="$ROOT_DIR/dist/404-distro.tar.gz"
DEFAULT_VERSION=${DISTRO_VERSION:-dev}
DEFAULT_IMAGE_TAG="404-distro-build:local"

STATIC_BINARY="$DEFAULT_STATIC_BINARY"
TTL_OBJECT="$DEFAULT_TTL_OBJECT"
DISTRO_VERSION_VALUE="$DEFAULT_VERSION"
OUTPUT_PATH="$DEFAULT_OUTPUT"
IMAGE_TAG="$DEFAULT_IMAGE_TAG"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --static-binary)
      STATIC_BINARY="$2"
      shift 2
      ;;
    --ttl-object)
      TTL_OBJECT="$2"
      shift 2
      ;;
    --version)
      DISTRO_VERSION_VALUE="$2"
      shift 2
      ;;
    --output)
      OUTPUT_PATH="$2"
      shift 2
      ;;
    --image-tag)
      IMAGE_TAG="$2"
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

command -v docker >/dev/null 2>&1 || {
  echo "docker is required to build the WSL distro tarball" >&2
  exit 1
}

[ -f "$STATIC_BINARY" ] || {
  echo "missing STATIC binary: $STATIC_BINARY" >&2
  echo "expected a prebuilt x86_64-unknown-linux-musl artifact" >&2
  exit 1
}

[ -f "$TTL_OBJECT" ] || {
  echo "missing eBPF object: $TTL_OBJECT" >&2
  echo "build it first from src/ebpf, for example: make -C src/ebpf" >&2
  exit 1
}

TMP_DIR=$(mktemp -d)
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

mkdir -p "$TMP_DIR/artifacts" "$TMP_DIR/rootfs/opt/404" "$TMP_DIR/rootfs/etc"
mkdir -p "$(dirname "$OUTPUT_PATH")"

cp -R "$DISTRO_DIR/rootfs/." "$TMP_DIR/rootfs/"
cp "$STATIC_BINARY" "$TMP_DIR/artifacts/static"
cp "$TTL_OBJECT" "$TMP_DIR/artifacts/ttl_editor.o"
printf '%s\n' "$DISTRO_VERSION_VALUE" > "$TMP_DIR/rootfs/opt/404/distro-version"

docker build \
  -f "$DISTRO_DIR/Dockerfile.build" \
  -t "$IMAGE_TAG" \
  "$TMP_DIR" >/dev/null

CONTAINER_ID=$(docker create "$IMAGE_TAG")
docker export "$CONTAINER_ID" | gzip -n > "$OUTPUT_PATH"
docker rm "$CONTAINER_ID" >/dev/null

echo "built $OUTPUT_PATH"
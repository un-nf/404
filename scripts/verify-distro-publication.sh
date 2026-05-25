#!/bin/sh
set -eu

usage() {
  cat <<'EOF'
Usage: ./scripts/verify-distro-publication.sh --base-url URL --version TAG

Checks that:
  - URL/distro/manifest.json is reachable
  - URL/distro/manifest.json.sig is reachable
  - the stable manifest points at /distro/TAG/404-distro.tar.gz
  - the versioned tarball is reachable

Example:
  ./scripts/verify-distro-publication.sh \
    --base-url https://updates.404privacy.com \
    --version v1.2.3
EOF
}

BASE_URL=""
EXPECTED_VERSION=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --base-url)
      BASE_URL="$2"
      shift 2
      ;;
    --version)
      EXPECTED_VERSION="$2"
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

[ -n "$BASE_URL" ] || {
  echo "--base-url is required" >&2
  exit 1
}

[ -n "$EXPECTED_VERSION" ] || {
  echo "--version is required" >&2
  exit 1
}

command -v curl >/dev/null 2>&1 || {
  echo "curl is required" >&2
  exit 1
}

command -v node >/dev/null 2>&1 || {
  echo "node is required" >&2
  exit 1
}

trimmed_base_url=${BASE_URL%/}
manifest_url="$trimmed_base_url/distro/manifest.json"
signature_url="$trimmed_base_url/distro/manifest.json.sig"

tmp_manifest=$(mktemp)
tmp_signature=$(mktemp)
cleanup() {
  rm -f "$tmp_manifest" "$tmp_signature"
}
trap cleanup EXIT INT TERM

curl --fail --silent --show-error --location "$manifest_url" --output "$tmp_manifest"
curl --fail --silent --show-error --location "$signature_url" --output "$tmp_signature"

EXPECTED_VERSION="$EXPECTED_VERSION" \
MANIFEST_PATH="$tmp_manifest" \
BASE_URL="$trimmed_base_url" \
node <<'EOF'
const fs = require('node:fs');

const manifestPath = process.env.MANIFEST_PATH;
const expectedVersion = process.env.EXPECTED_VERSION;
const baseUrl = process.env.BASE_URL;

if (!manifestPath || !expectedVersion || !baseUrl) {
  throw new Error('MANIFEST_PATH, EXPECTED_VERSION, and BASE_URL are required');
}

const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
const expectedArtifactPath = `/distro/${expectedVersion}/404-distro.tar.gz`;

if (manifest.version !== expectedVersion) {
  throw new Error(`stable manifest version mismatch: expected ${expectedVersion}, got ${manifest.version}`);
}

if (manifest.artifact_path !== expectedArtifactPath) {
  throw new Error(
    `stable manifest artifact_path mismatch: expected ${expectedArtifactPath}, got ${manifest.artifact_path}`,
  );
}

const tarballUrl = `${baseUrl}${manifest.artifact_path}`;
process.stdout.write(`${tarballUrl}\n`);
EOF

tarball_url=$(EXPECTED_VERSION="$EXPECTED_VERSION" MANIFEST_PATH="$tmp_manifest" BASE_URL="$trimmed_base_url" node <<'EOF'
const fs = require('node:fs');

const manifest = JSON.parse(fs.readFileSync(process.env.MANIFEST_PATH, 'utf8'));
process.stdout.write(`${process.env.BASE_URL}${manifest.artifact_path}`);
EOF
)

curl --fail --silent --show-error --location --head "$tarball_url" >/dev/null

echo "Verified stable distro manifest: $manifest_url"
echo "Verified stable distro signature: $signature_url"
echo "Verified versioned tarball: $tarball_url"
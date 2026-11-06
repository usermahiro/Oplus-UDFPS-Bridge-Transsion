#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROFILE="${1:-release}"

case "$PROFILE" in
  release|debug) ;;
  *) echo "Usage: $0 [release|debug]" >&2; exit 2 ;;
esac

"$SCRIPT_DIR/build.sh" "$PROFILE"

PACKAGE="$SCRIPT_DIR/out/transsion-vendor-fod-package.zip"
if [[ ! -f "$PACKAGE" ]]; then
  echo "Build did not produce $PACKAGE" >&2
  exit 1
fi

VERSION="$(awk -F'"' '/^version = / { print $2; exit }' "$SCRIPT_DIR/Cargo.toml")"
NAME="oplus-udfps-bridge-transsion-v${VERSION}-${PROFILE}.zip"
cp -f "$PACKAGE" "$SCRIPT_DIR/out/$NAME"

# Generate checksum with relative filename
(cd "$SCRIPT_DIR/out" && sha256sum "$NAME" > "$NAME.sha256")

echo "Package created: $SCRIPT_DIR/out/$NAME"
echo "Checksum: $SCRIPT_DIR/out/$NAME.sha256"

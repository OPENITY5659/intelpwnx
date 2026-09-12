#!/usr/bin/env bash
# Load PwnSolver x86_64 sandbox image from a release tar.zst.
# Download example:
#   gh release download v0.1.0-x86-image -R OPENITY5659/intelpwnx -p pwnsolver-x86.tar.zst
# Then:
#   scripts/load-x86-image.sh ./pwnsolver-x86.tar.zst
set -euo pipefail
FILE="${1:-pwnsolver-x86.tar.zst}"
if [ ! -f "$FILE" ]; then
  echo "usage: $0 <pwnsolver-x86.tar.zst>" >&2
  exit 2
fi
zstd -d -c "$FILE" | docker load
echo "[+] loaded. Verify: docker run --platform linux/amd64 --rm pwnsolver-x86:latest one_gadget --version"

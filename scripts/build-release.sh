#!/usr/bin/env bash
# Build cross-platform release archives for sweetty, with checksums. Run by the
# release workflow on a tag, and usable locally for a dry run (make release-local).
set -euo pipefail

cd "$(dirname "$0")/.."

VERSION="${VERSION:-$(git describe --tags --exact-match 2>/dev/null || git describe --tags --always --dirty 2>/dev/null || echo dev)}"
GIT_COMMIT="${GIT_COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo none)}"
BUILD_DATE="${BUILD_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
OUT="${OUT:-dist}"
VER_NOV="${VERSION#v}"

LDFLAGS="-s -w -X main.version=${VERSION} -X main.gitCommit=${GIT_COMMIT} -X main.buildDate=${BUILD_DATE}"

targets=(
  "linux/amd64"
  "linux/arm64"
  "darwin/amd64"
  "darwin/arm64"
)

rm -rf "$OUT"
mkdir -p "$OUT"

for t in "${targets[@]}"; do
  goos="${t%/*}"
  goarch="${t#*/}"
  stage="$(mktemp -d)"
  echo "building ${goos}/${goarch}"
  # Build the linux targets as PIE so the whole image base is ASLR-randomized at
  # load; a non-PIE ET_EXEC sits at a fixed address and hands gadget addresses to an
  # exploit. CGO stays disabled (static, internal-linked PIE). darwin is already
  # PIE, so gate the flag to linux.
  buildmode=""
  [ "$goos" = "linux" ] && buildmode="-buildmode=pie"
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
    go build $buildmode -trimpath -ldflags "$LDFLAGS" -o "$stage/sweetty" ./cmd/sweetty
  for f in README.md VISION.md LICENSE; do
    [ -f "$f" ] && cp "$f" "$stage/"
  done
  tar -C "$stage" -czf "$OUT/sweetty_${VER_NOV}_${goos}_${goarch}.tar.gz" .
  rm -rf "$stage"
done

( cd "$OUT" && { sha256sum ./*.tar.gz 2>/dev/null || shasum -a 256 ./*.tar.gz; } > checksums.txt )

echo "artifacts in ${OUT}:"
ls -1 "$OUT"

#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DIST="${SCRIPT_DIR}/dist"
BUILD_DARWIN=false

for arg in "$@"; do
    case "${arg}" in
        -build-darwin)  BUILD_DARWIN=true ;;
        *) echo "Unknown argument: ${arg}" >&2; exit 1 ;;
    esac
done

mkdir -p "${DIST}"

# Linux targets are built inside Docker using platform emulation.
# Requires Docker Desktop (macOS) or QEMU binfmt support on Linux hosts.
for PLATFORM in linux/amd64 linux/arm64; do
    OS="${PLATFORM%%/*}"
    ARCH="${PLATFORM##*/}"
    TMP_DIR="$(mktemp -d)"
    echo "==> ${PLATFORM}"
    DOCKER_BUILDKIT=1 docker build \
        --platform "${PLATFORM}" \
        --target binary \
        --output "type=local,dest=${TMP_DIR}" \
        "${SCRIPT_DIR}"
    mv "${TMP_DIR}/rduck-web" "${DIST}/rduck-web-${OS}-${ARCH}"
    rm -rf "${TMP_DIR}"
done

# macOS binaries cannot be produced by Docker; they must be built natively.
if [[ "${BUILD_DARWIN}" == true ]]; then
    echo "==> darwin/arm64 (native)"
    GOARCH=arm64 GOOS=darwin CGO_ENABLED=1 \
        go build -o "${DIST}/rduck-web-darwin-arm64" \
        "${SCRIPT_DIR}/cmd/rduck-web"
fi
#!/bin/sh
# Builds foca for Linux. There is no helper on Linux, so this is a plain
# static build; it exists so release builds and local ones are the same.
#
#   scripts/build-linux.sh <amd64|arm64> [out-dir]     (default: bin)
#
# FOCA_VERSION: the version `foca version` reports. Default: the one in
# cmd/foca.
set -eu

cd "$(dirname "$0")/.."
arch=${1:?usage: scripts/build-linux.sh <amd64|arm64> [out-dir]}
out=${2:-bin}
mkdir -p "$out"

ldflags="-s -w"
if [ -n "${FOCA_VERSION:-}" ]; then
	ldflags="$ldflags -X main.version=$FOCA_VERSION"
fi
# GOFLAGS is cleared so a -tags=foca_testing left in the environment can't
# turn this into a test build, which accepts the always-approving fake
# authenticator. The check after the build makes sure.
env GOFLAGS= CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -ldflags "$ldflags" \
	-o "$out/foca" ./cmd/foca
if go version -m "$out/foca" | grep -q 'foca_testing'; then
	echo "$out/foca was built with the foca_testing tag; refusing it" >&2
	rm -f "$out/foca"
	exit 1
fi

echo "built $out/foca (linux/$arch)"

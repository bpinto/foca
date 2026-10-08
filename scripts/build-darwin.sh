#!/bin/sh
# Builds foca and foca-darwin for macOS, with the helper's sha256 pinned
# into foca. foca runs no helper without the pin (design §5), so this is how
# a Mac build is made.
#
#   scripts/build-darwin.sh [out-dir]          (default: bin)
#
# FOCA_SIGN_IDENTITY: codesign identity for foca-darwin. Default "-", an
# ad-hoc signature. A Developer ID identity gives the helper a code identity
# that survives rebuilds, so the Keychain doesn't ask again after an update.
# FOCA_VERSION: the version `foca version` reports. Default: the one in
# cmd/foca.
set -eu

cd "$(dirname "$0")/.."
out=${1:-bin}
identity=${FOCA_SIGN_IDENTITY:--}
mkdir -p "$out"

(cd helpers/darwin && swift build -c release)
rm -f "$out/foca-darwin"
cp helpers/darwin/.build/release/foca-darwin "$out/foca-darwin"
chmod 755 "$out/foca-darwin"

# Sign before hashing: signing rewrites the file, and the pin must match
# the file that runs.
codesign --force --sign "$identity" --identifier io.github.bpinto.foca-darwin \
	--options runtime "$out/foca-darwin"
codesign --verify --strict "$out/foca-darwin"
sum=$(shasum -a 256 "$out/foca-darwin" | cut -d ' ' -f 1)

# GOFLAGS is cleared so a -tags=foca_testing left in the environment can't
# turn this into a test build, which accepts the always-approving fake
# authenticator. The check after the build makes sure.
ldflags="-X github.com/bpinto/foca/internal/server/wiring.builtinHelperSHA256=$sum"
if [ -n "${FOCA_VERSION:-}" ]; then
	ldflags="$ldflags -X main.version=$FOCA_VERSION"
fi
env GOFLAGS= CGO_ENABLED=0 go build -trimpath -ldflags "$ldflags" \
	-o "$out/foca" ./cmd/foca
if go version -m "$out/foca" | grep -q 'foca_testing'; then
	echo "$out/foca was built with the foca_testing tag; refusing it" >&2
	rm -f "$out/foca"
	exit 1
fi

echo "built $out/foca and $out/foca-darwin (sha256 $sum, signed by $identity)"

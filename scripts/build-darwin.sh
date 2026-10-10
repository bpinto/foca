#!/bin/sh
# Builds foca, foca-darwin and Foca.app for macOS, with the helper's sha256
# pinned into foca. foca runs no helper without the pin (design §5), so this
# is how a Mac build is made.
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

# Foca.app, the menu-bar app (design §8.7): the Foca executable in a bundle,
# so macOS knows it by its bundle id, as notifications need. foca never runs
# it, so it needs no pin.
(cd apps/macos && swift build -c release --product Foca)
app="$out/Foca.app"
rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
cp apps/macos/.build/release/Foca "$app/Contents/MacOS/Foca"
cp apps/macos/Info.plist "$app/Contents/Info.plist"
# The pixel-art icons (scripts/pixelart): the app icon, and the menu-bar
# templates.
iconutil -c icns apps/macos/Resources/Foca.iconset -o "$app/Contents/Resources/Foca.icns"
cp apps/macos/Resources/MenuBarIcon*.png "$app/Contents/Resources/"
if [ -n "${FOCA_VERSION:-}" ]; then
	# CFBundleShortVersionString takes numbers only: the X.Y.Z of the version.
	short=$(echo "$FOCA_VERSION" | sed -E 's/^([0-9]+\.[0-9]+\.[0-9]+).*/\1/')
	plutil -replace CFBundleShortVersionString -string "$short" "$app/Contents/Info.plist"
fi
codesign --force --sign "$identity" --options runtime "$app"
codesign --verify --strict "$app"

echo "built $out/foca, $out/foca-darwin (sha256 $sum) and $out/Foca.app, signed by $identity"

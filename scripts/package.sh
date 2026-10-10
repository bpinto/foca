#!/bin/sh
# Packs a build of scripts/build-linux.sh or build-darwin.sh into its release
# archive, foca-<platform>.tar.gz in the current directory.
#
#   scripts/package.sh linux-amd64|linux-arm64|darwin-arm64 <out-dir>
set -eu
platform=$1
out=$2
case $platform in
linux-amd64 | linux-arm64) files=foca ;;
darwin-arm64) files="foca foca-darwin Foca.app" ;;
*)
	echo "unknown platform $platform" >&2
	exit 2
	;;
esac
root=$(cd "$(dirname "$0")/.." && pwd)
cp "$root/LICENSE" "$root/README.md" "$out/"
# shellcheck disable=SC2086 # files is a list of names
tar -czf "foca-$platform.tar.gz" -C "$out" $files LICENSE README.md

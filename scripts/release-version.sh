#!/bin/sh
# Prints the version of a rolling build of a commit:
# <next patch>-<kind>.<commit date, UTC, YYYYMMDD>+<short sha>, where
# <next patch> follows the newest stable tag the commit contains (pre-release
# tags don't count). The commit's date, not the build's, so a rebuild of the
# same commit gets the same version. Needs the tags (fetch-depth 0).
#
#   scripts/release-version.sh tip|pr.<N> <sha>
set -eu
kind=$1
sha=$2
last=$(git tag --merged "$sha" --list 'v*' --sort=-v:refname | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | head -n 1 || true)
if [ -n "$last" ]; then
	v=${last#v}
	major=${v%%.*}
	rest=${v#*.}
	minor=${rest%%.*}
	patch=${rest#*.}
	next="$major.$minor.$((patch + 1))"
else
	next=0.1.0
fi
date=$(TZ=UTC git show -s --format=%cd --date=format-local:%Y%m%d "$sha")
echo "$next-$kind.$date+$(echo "$sha" | cut -c1-7)"

#!/usr/bin/env bash
# Download the pinned CRS regression suite into ./crs-tests. `seaweed false-positives`
# reads the stages whose expectation is that a rule does not fire, and replays them.
# The directory is managed by this script and is replaced wholesale.
#
# Pinning matters for the same reason it does for the Nuclei templates: the corpus is what
# the number is measured against, so it has to move deliberately.
set -euo pipefail

# renovate: datasource=github-releases depName=coreruleset/coreruleset
version="${CRS_VERSION:-v4.28.0}"

cd "$(dirname "$0")/.."

target=crs-tests
url="https://github.com/coreruleset/coreruleset/archive/refs/tags/${version}.tar.gz"

rm -rf "${target}"
mkdir -p "${target}"
curl -fsSL "${url}" |
	tar xz -C "${target}" --strip-components=4 "coreruleset-${version#v}/tests/regression/tests"

echo "fetched the ${version} regression suite into ${target}/"

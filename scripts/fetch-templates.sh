#!/usr/bin/env bash
# Download the pinned Nuclei templates into ./nuclei-templates, which both the scan and
# `seaweed gen-mock` read. The directory is managed by this script and is replaced
# wholesale, so do not keep anything of your own in it.
#
# Pinning the version is what makes one week's numbers comparable to the next. Bumping it
# changes the results on purpose, and CI will fail until mock/fingerprints.html is
# regenerated from the new version in the same change.
set -euo pipefail

# renovate: datasource=github-releases depName=projectdiscovery/nuclei-templates
version="${NUCLEI_TEMPLATES_VERSION:-v10.4.7}"

cd "$(dirname "$0")/.."

target=nuclei-templates
url="https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/${version}.tar.gz"

rm -rf "${target}"
mkdir -p "${target}"
curl -fsSL "${url}" | tar xz -C "${target}" --strip-components=1

echo "fetched nuclei-templates ${version} into ${target}/"

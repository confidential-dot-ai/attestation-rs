#!/usr/bin/env bash
# Give the image CI built from a commit the release's name, without rebuilding.
#
#   name-image-release.sh vMAJOR.MINOR.PATCH COMMIT_SHA
#
# CI pushes ghcr.io/confidential-dot-ai/attestation-api:sha-<7> for every main
# commit. A release names one of those commits; this adds the tag vX.Y.Z to the
# same manifest, so consumers pinning the version and consumers pinning the
# commit resolve one digest. Fails when the sha- tag is not published or the
# two names disagree afterwards. Needs a docker CLI logged in to ghcr.io.

set -euo pipefail

die() {
  echo "name-image-release: $*" >&2
  exit 1
}

[[ $# -eq 2 ]] || die "usage: name-image-release.sh vMAJOR.MINOR.PATCH COMMIT_SHA"
version="$1"
commit="$2"
[[ "$version" =~ ^v(0|[1-9][0-9]*)[.](0|[1-9][0-9]*)[.](0|[1-9][0-9]*)$ ]] ||
  die "$version is not a release version (vMAJOR.MINOR.PATCH)"
[[ "$commit" =~ ^[0-9a-f]{40}$ ]] || die "commit must be a full lowercase 40-hex SHA"

image=${IMAGE:-ghcr.io/confidential-dot-ai/attestation-api}
source="$image:sha-${commit:0:7}"
target="$image:$version"

digest_of() {
  docker buildx imagetools inspect --format '{{.Manifest.Digest}}' "$1"
}

source_digest=$(digest_of "$source") || die "$source is not published; the release commit's CI image must exist first"

# Only a confirmed absence may proceed to tagging: imagetools create would
# repoint an existing version tag, so any other inspect failure stops here.
existing=""
if ! existing=$(digest_of "$target" 2>&1); then
  [[ "$existing" == *"not found"* ]] || die "could not inspect $target: $existing"
  existing=""
fi
if [[ -n "$existing" ]]; then
  [[ "$existing" == "$source_digest" ]] ||
    die "$target already names $existing, not $source_digest; a release tag is never repointed"
  echo "$target already names $source_digest"
  exit 0
fi
docker buildx imagetools create -t "$target" "$source"
target_digest=$(digest_of "$target")
[[ "$target_digest" == "$source_digest" ]] ||
  die "$target resolved to $target_digest after tagging, expected $source_digest"
echo "$target names $source_digest"

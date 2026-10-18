#!/usr/bin/env bash
# Refuse to build a release for a tag that was moved after its release was
# made (BUILD-STATUS P10). A second push of an existing tag starts
# release.yml again; without this check GoReleaser would find the existing
# release by its tag name and replace its assets and images with a build
# of another commit, so a published release, its signatures and every
# sprout that trusts them would silently change underneath.
#
# Every release made by GoReleaser records the commit it was built from as
# its target_commitish (.goreleaser.yaml, release.target_commitish). This
# script looks the tag's release up (drafts included) before anything is
# built:
#   - no release for the tag yet                       -> pass
#   - target_commitish is the commit being built       -> pass (a re-run)
#   - target_commitish is another commit               -> fail
#   - target_commitish is not a commit (a release made in the GitHub UI,
#     which records a branch name, or one built before the commit was
#     recorded) and the release has no assets yet       -> pass
#   - the same, but the release already has assets     -> fail: it was
#     built, and what from cannot be checked
# A tag is never moved: cut the next pre-release instead (docs/RELEASING.md,
# "A tag never moves").
#
# Usage: check-release-tag.sh <repository> <tag> <commit>
#   <repository>  owner/name, e.g. "$GITHUB_REPOSITORY"
#   <tag>         the tag being released, e.g. "$GITHUB_REF_NAME"
#   <commit>      the full commit SHA being built, e.g. "$GITHUB_SHA"
# Needs gh (GH_TOKEN with contents: read; a token that can write contents
# also sees draft releases, which the tags endpoint never returns) and jq.
set -euo pipefail

die() {
	echo "::error::$*" >&2
	exit 1
}

[ "$#" -eq 3 ] || {
	echo "usage: check-release-tag.sh <repository> <tag> <commit>" >&2
	exit 2
}
repository="$1"
tag="$2"
commit="$3"
[[ "$commit" =~ ^[0-9a-f]{40}$ ]] || die "'$commit' is not a full commit SHA"

# Every release, drafts included; the tags endpoint skips drafts.
releases="$(gh api --paginate "repos/${repository}/releases?per_page=100")" ||
	die "could not list the releases of ${repository}"
found="$(jq -cs --arg t "$tag" '
	[.[][] | select(.tag_name == $t)] | .[0] // empty
	| {target: (.target_commitish // ""), draft: .draft, assets: (.assets | length), url: .html_url}
' <<<"$releases")"

if [ -z "$found" ]; then
	echo "no release for $tag yet"
	exit 0
fi

target="$(jq -r .target <<<"$found")"
assets="$(jq -r .assets <<<"$found")"
url="$(jq -r .url <<<"$found")"
state="published"
[ "$(jq -r .draft <<<"$found")" = "true" ] && state="draft"

if [[ "$target" =~ ^[0-9a-f]{40}$ ]]; then
	if [ "$target" = "$commit" ]; then
		echo "the $state release for $tag was built from $commit, the commit $tag points at: a re-run, allowed"
		exit 0
	fi
	die "$tag now points at $commit, but its $state release ($url) was built from $target: a tag never moves. Put the tag back (git push --force origin $target:refs/tags/$tag) or leave it and release the fix as the next pre-release, e.g. tag a new -rc.N (docs/RELEASING.md, \"A tag never moves\")"
fi

if [ "$assets" -eq 0 ]; then
	echo "the $state release for $tag records no commit (target '$target') and has no assets yet: not built before, allowed"
	exit 0
fi
die "the $state release for $tag ($url) already has $assets assets and records no commit it was built from (target '$target'), so whether $tag moved cannot be checked: it is not built again. Release the change as the next pre-release, e.g. tag a new -rc.N (docs/RELEASING.md, \"A tag never moves\")"

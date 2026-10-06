#!/usr/bin/env bash
# admin-keys.sh <kubeconfig> <endpoints.json> <state-dir> <release_tag>
#
# Makes the bootstrap admin's keys (deploy/helm/farmer README, "Bootstrap
# admin") with the imas CLI of the release under test: imas auth privkey,
# imas auth pubkey and imas auth keygen, offline, in a HOME of its own.
# FLAG FOR SECURITY REVIEW.
#
# The CLI comes from the GitHub release named by release_tag, checked
# against the release's checksums.txt (signature verification of
# checksums.txt is not done here; see README.md, "Deferred").
#
# Writes:
#   <state>/core/out/admin.json        public halves: pubkey, boxpub,
#                                      fingerprint, username (not secret;
#                                      gen-values.sh reads it)
#   <state>/core/sensitive/admin-home  the admin's CLI HOME:
#                                      .config/imas/imas (holds the NKey
#                                      private key) and cli-box.key. SENSITIVE.
#   <state>/core/sensitive/admin.json  where those files are, for the tests
# A re-run reuses the keys it finds: the admin's identity must not change
# under a running farmer (it imports the box key once).
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib/common.sh
. "$here/lib/common.sh"
parse_common_args "admin-keys.sh <kubeconfig> <endpoints.json> <state-dir> <release_tag>" "$@"
[[ $# -ge 4 ]] || die "usage: admin-keys.sh <kubeconfig> <endpoints.json> <state-dir> <release_tag>"
release_tag="$4"
version=$(release_version "$release_tag")
need_cmd curl tar jq sha256sum

case "$(uname -m)" in
x86_64 | amd64) arch=amd64 ;;
aarch64 | arm64) arch=arm64 ;;
*) die "unsupported runner architecture: $(uname -m)" ;;
esac

imas="$STATE_DIR/bin/imas-$version"
if [[ ! -x "$imas" ]]; then
	dl="$STATE_DIR/bin/download-$version"
	mkdir -p "$dl"
	archive="imas-$version-linux-$arch.tar.gz"
	log "downloading $archive and checksums.txt from release $release_tag"
	curl -fsSL --retry 3 --proto '=https' -o "$dl/$archive" "$IMAS_RELEASE_BASE_URL/$release_tag/$archive" ||
		die "could not download $archive from release $release_tag"
	curl -fsSL --retry 3 --proto '=https' -o "$dl/checksums.txt" "$IMAS_RELEASE_BASE_URL/$release_tag/checksums.txt" ||
		die "could not download checksums.txt from release $release_tag"
	want=$(awk -v f="$archive" '$2 == f { print $1 }' "$dl/checksums.txt")
	[[ "$want" =~ ^[0-9a-f]{64}$ ]] || die "checksums.txt of $release_tag has no entry for $archive"
	got=$(sha256sum "$dl/$archive" | awk '{ print $1 }')
	[[ "$got" == "$want" ]] || die "$archive does not match checksums.txt ($got != $want)"
	tar -xzf "$dl/$archive" -C "$dl" "imas-$version-linux-$arch" ||
		die "$archive has no imas-$version-linux-$arch binary"
	mv "$dl/imas-$version-linux-$arch" "$imas"
	chmod 755 "$imas"
	rm -rf "$dl"
fi

admin_home="$SENSITIVE_DIR/admin-home"
cfg_dir="$admin_home/.config/imas"
(umask 077 && mkdir -p "$cfg_dir")
chmod 700 "$admin_home" "$admin_home/.config" "$cfg_dir"

# The CLI resolves its config from HOME only. Its own stdout is captured;
# only public keys are ever printed by these three commands.
cli() { env -u XDG_CONFIG_HOME HOME="$admin_home" "$imas" "$@" </dev/null; }

pub_out="$OUT_DIR/admin.json"
if [[ -s "$pub_out" && -s "$cfg_dir/cli-box.key" ]]; then
	log "reusing the bootstrap admin keys in $admin_home"
else
	if ! cli auth pubkey >/dev/null 2>&1; then
		cli auth privkey >/dev/null 2>&1 || die "imas auth privkey failed"
	fi
	pubkey=$(cli auth pubkey 2>/dev/null | tail -n1 | tr -d '[:space:]')
	[[ "$pubkey" =~ ^[A-Z2-7]{56}$ ]] || die "imas auth pubkey printed no NKey public key"
	keygen=$(cli --out json auth keygen 2>/dev/null) || die "imas auth keygen failed: $(jq -r '.error // empty' <<<"$keygen" 2>/dev/null)"
	jq -n --argjson k "$keygen" --arg pubkey "$pubkey" --arg username "$BOOTSTRAP_ADMIN_NAME" \
		--arg tag "$release_tag" '{
		  pubkey: $pubkey, boxpub: $k.box_pub, fingerprint: $k.fingerprint,
		  username: $username, cli_release: $tag
		}' >"$pub_out"
	[[ "$(jq -r .pubkey "$pub_out")" == "$(jq -r '.user // empty' <<<"$keygen")" ]] ||
		die "imas auth keygen reported a different user than imas auth pubkey"
fi
# The CLI writes its config file (with the NKey private key) 0644; tighten it.
chmod 600 "$cfg_dir/imas" "$cfg_dir/cli-box.key"

(umask 077 && jq -n --arg home "$admin_home" --arg cfg "$cfg_dir/imas" --arg box "$cfg_dir/cli-box.key" \
	--arg cli "$imas" --slurpfile pub "$pub_out" '$pub[0] + {
	  home: $home, config_file: $cfg, box_key_file: $box, cli: $cli,
	  note: "SENSITIVE: config_file holds the bootstrap admin NKey private key, box_key_file its CLI box private key. Run the CLI with HOME set to home."
	}' >"$SENSITIVE_DIR/admin.json")
log "bootstrap admin: $(jq -r '.pubkey' "$pub_out"), box key fingerprint $(jq -r '.fingerprint' "$pub_out")"

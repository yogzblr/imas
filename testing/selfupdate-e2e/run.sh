#!/usr/bin/env bash
# End-to-end test of a sprout self-update (FU.2), against a real package
# repository (Sonatype Nexus Repository Community Edition), with no part of
# the update path mocked:
#
#   1. builds imas-sprout v0.1.0 and v0.2.0 and packages them as .deb and
#      .rpm (the .goreleaser.yaml nfpm contents, including the fleet signing
#      keyring);
#   2. starts the stub farmer (ansible/molecule/stubfarmer): enrollment, the
#      bus, the signed update manifest endpoint, sealed cook dispatch, and a
#      TLS proxy in front of Nexus with its own CA;
#   3. publishes the packages to signed apt and yum hosted repositories in
#      Nexus;
#   4. in a systemd container per distro, installs imas-sprout v0.1.0 from
#      Nexus with the OS package manager, trusts the repository CA in the
#      OS trust store, pins the farmer CA as SproutRootCA, and starts the
#      sprout, which enrolls and connects to the bus;
#   5. registers v0.2.0 (signed manifest) and sends the sprout a sealed
#      self_update job;
#   6. checks the sprout found the package in the repository's index,
#      installed it with dpkg/rpm, restarted onto the new binary and
#      reconnected announcing v0.2.0;
#   7. checks the refusals on the updated sprout: a downgrade, a manifest
#      signed by an untrusted key, a release whose checksum isn't in the
#      repository, and a version with no manifest. None changes the
#      installed package.
#
# Nexus Repository Community Edition (the current sonatype/nexus3 image)
# refuses to create repositories until its End User License Agreement
# (https://links.sonatype.com/products/nxrm/ce-eula) is accepted. Accepting
# it is yours to do: the script accepts it for its throwaway container only
# when NEXUS_ACCEPT_EULA=1 is set, and otherwise stops before using Nexus.
#
# Usage: NEXUS_ACCEPT_EULA=1 testing/selfupdate-e2e/run.sh   (from the repo root)
# Env:   NEXUS_ACCEPT_EULA=1      you accept the Nexus CE EULA (required)
#        DISTROS="debian rocky"   which sprouts to test (default: both;
#                                 an image that can't be pulled is skipped)
#        KEEP=1                   leave the containers running afterwards
#        WORK=dir                 work directory (default: a temp dir)
#
# Needs docker (systemd containers need --privileged), go, curl and jq.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
work="${WORK:-$(mktemp -d)}"
distros="${DISTROS:-debian rocky}"
net=imase2e
nexus_image="${NEXUS_IMAGE:-mirror.gcr.io/sonatype/nexus3:latest}"
helper_image="${HELPER_IMAGE:-mirror.gcr.io/dokken/debian-12:latest}"
declare -A sprout_image=(
	[debian]="${DEBIAN_IMAGE:-mirror.gcr.io/dokken/debian-12:latest}"
	[rocky]="${ROCKY_IMAGE:-mirror.gcr.io/dokken/rockylinux-9:latest}"
)
nfpm="github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.47.0"
join_token="e2ekey.e2esecret"
# The private repository's read token: the password of a read-only Nexus
# user named "buildkite", the user the sprout (and the Ansible role) sends.
repo_token="e2e-$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')"
farmer_port=15405
nexus_port=18081
v1=0.1.0
v2=0.2.0

pass=0
fail=0
log() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok() { printf '  \033[32mPASS\033[0m %s\n' "$*"; pass=$((pass + 1)); }
bad() { printf '  \033[31mFAIL\033[0m %s\n' "$*"; fail=$((fail + 1)); }
die() { echo "selfupdate-e2e: $*" >&2; exit 1; }

containers=(e2e-farmer e2e-nexus e2e-sprout-debian e2e-sprout-rocky)
cleanup() {
	if [[ -n "${KEEP:-}" ]]; then
		echo "KEEP set: leaving ${containers[*]} running; work dir $work"
		return
	fi
	docker rm -f "${containers[@]}" >/dev/null 2>&1 || true
	docker network rm "$net" >/dev/null 2>&1 || true
}
trap cleanup EXIT

for tool in docker go curl jq; do command -v "$tool" >/dev/null || die "$tool not found"; done
[[ "${NEXUS_ACCEPT_EULA:-}" == 1 ]] || die "set NEXUS_ACCEPT_EULA=1 to accept the Nexus Repository Community Edition EULA (https://links.sonatype.com/products/nxrm/ce-eula) for the test container"
mkdir -p "$work"/{bin,pkg,state,nfpm,gpg}
chmod 777 "$work/state"
echo "work dir: $work"

# --- 1. Build ------------------------------------------------------------
log "Building the stub farmer and imas-sprout $v1, $v2"
(
	cd "$repo_root"
	CGO_ENABLED=0 go build -trimpath -o "$work/bin/stubfarmer" ./ansible/molecule/stubfarmer
	for v in "$v1" "$v2"; do
		CGO_ENABLED=0 go build -trimpath -ldflags "-X main.Tag=v$v" -o "$work/bin/imas-sprout-$v" ./cmd/sprout
	done
)

# --- 2. Stub farmer and Nexus -------------------------------------------
log "Starting Nexus and the stub farmer"
docker rm -f "${containers[@]}" >/dev/null 2>&1 || true
docker network create "$net" >/dev/null 2>&1 || true
docker run -d --name e2e-nexus --network "$net" -p "127.0.0.1:$nexus_port:8081" "$nexus_image" >/dev/null
docker run -d --name e2e-farmer --network "$net" --network-alias farmer --network-alias repo \
	-p "127.0.0.1:$farmer_port:5405" -v "$work:/work" "$helper_image" \
	/work/bin/stubfarmer -addr :5405 -nats-port 5406 -hosts farmer -nats-urls tls://farmer:5406 \
	-join-token "$join_token" -state-dir /work/state \
	-repo-proxy-to http://e2e-nexus:8081 -repo-proxy-addr :8443 -repo-hosts repo >/dev/null
for _ in $(seq 1 30); do [[ -s "$work/state/fleet-signing-keys.json" && -s "$work/state/repo-ca.pem" ]] && break; sleep 1; done
[[ -s "$work/state/fleet-signing-keys.json" ]] || { docker logs e2e-farmer; die "the stub farmer did not start"; }

farmer() { # farmer METHOD PATH [JSON]
	curl -sS --noproxy '*' --fail-with-body --cacert "$work/state/ca.pem" --resolve "farmer:$farmer_port:127.0.0.1" \
		-X "$1" ${3:+-H 'Content-Type: application/json' -d "$3"} "https://farmer:$farmer_port$2"
}

# --- 3. Packages ---------------------------------------------------------
log "Packaging imas-sprout as .deb and .rpm (keyring: the stub's fleet signing key)"
for v in "$v1" "$v2"; do
	for fmt in deb rpm; do
		unit=/lib/systemd/system/imas-sprout.service
		[[ $fmt == rpm ]] && unit=/usr/lib/systemd/system/imas-sprout.service
		cat >"$work/nfpm/$fmt-$v.yaml" <<EOF
name: imas-sprout
arch: amd64
platform: linux
version: "$v"
maintainer: imas selfupdate e2e
description: IMAS remote control agent
license: 0BSD
contents:
  - src: $work/bin/imas-sprout-$v
    dst: /usr/bin/imas-sprout
    file_info: {mode: 0755}
  - src: $repo_root/packaging/etc/imas-sprout.conf
    dst: /etc/imas/sprout
    type: config|noreplace
    file_info: {mode: 0644}
  - src: $work/state/fleet-signing-keys.json
    dst: /etc/imas/fleet-signing-keys.json
    file_info: {mode: 0644}
  - dst: /var/cache/imas/sprout
    type: dir
    file_info: {mode: 0755}
  - src: $repo_root/packaging/systemd/imas-sprout.service
    dst: $unit
    type: config
    file_info: {mode: 0644}
scripts:
  postinstall: $repo_root/packaging/scripts/imas-sprout-$fmt-postinstall.sh
EOF
		(cd "$work" && go run "$nfpm" package --config "nfpm/$fmt-$v.yaml" --packager "$fmt" \
			--target "pkg/imas-sprout_${v}_linux_amd64.$fmt" >/dev/null)
	done
done
ls -l "$work/pkg"

# --- 4. Nexus repositories -----------------------------------------------
log "Creating signed apt and yum repositories in Nexus"
for _ in $(seq 1 90); do
	[[ "$(curl -s --noproxy '*' -o /dev/null -w '%{http_code}' "http://127.0.0.1:$nexus_port/service/rest/v1/status/writable")" == 200 ]] && break
	sleep 5
done
for _ in $(seq 1 30); do docker exec e2e-nexus test -s /nexus-data/admin.password && break; sleep 2; done
nexus_pw="$(docker exec e2e-nexus cat /nexus-data/admin.password)"
nexus() { # nexus METHOD PATH [curl args...]
	local m="$1" p="$2"
	shift 2
	curl -sS --noproxy '*' --fail-with-body -u "admin:$nexus_pw" -X "$m" "http://127.0.0.1:$nexus_port/service/rest$p" "$@"
}

# NEXUS_ACCEPT_EULA=1 (checked above): accept the CE EULA, echoing back the
# disclaimer Nexus asks to be returned.
nexus GET /v1/system/eula | jq '.accepted = true' | nexus POST /v1/system/eula -H 'Content-Type: application/json' -d @- >/dev/null
[[ "$(nexus GET /v1/system/eula | jq -r .accepted)" == true ]] || die "Nexus did not record the EULA acceptance"

docker run --rm -v "$work/gpg:/gpg" "$helper_image" sh -ec '
	export GNUPGHOME=$(mktemp -d)
	gpg --batch --quiet --passphrase "" --quick-gen-key "imas selfupdate e2e <e2e@imas.invalid>" rsa3072 sign never
	gpg --batch --armor --export-secret-keys > /gpg/private.asc
	gpg --batch --armor --export > /gpg/public.asc
	chmod 644 /gpg/*.asc'
storage='"storage":{"blobStoreName":"default","strictContentTypeValidation":true,"writePolicy":"allow"}'
nexus POST /v1/repositories/apt/hosted -H 'Content-Type: application/json' -d "$(jq -n \
	--rawfile key "$work/gpg/private.asc" --argjson storage "{$storage}" \
	'{name:"imas-apt", online:true, storage:$storage.storage, apt:{distribution:"any"}, aptSigning:{keypair:$key, passphrase:""}}')"
nexus POST /v1/repositories/yum/hosted -H 'Content-Type: application/json' -d \
	"{\"name\":\"imas-yum\",\"online\":true,$storage,\"yum\":{\"repodataDepth\":0,\"deployPolicy\":\"STRICT\"}}"
# No anonymous access (Nexus's default): a read-only user stands in for the
# private registry's token.
nexus POST /v1/security/roles -H 'Content-Type: application/json' -d '{"id":"imas-read","name":"imas-read","description":"read imas packages",
	"privileges":["nx-repository-view-apt-imas-apt-browse","nx-repository-view-apt-imas-apt-read",
	"nx-repository-view-yum-imas-yum-browse","nx-repository-view-yum-imas-yum-read"],"roles":[]}' >/dev/null
nexus POST /v1/security/users -H 'Content-Type: application/json' -d "$(jq -n --arg pw "$repo_token" \
	'{userId:"buildkite", firstName:"imas", lastName:"e2e", emailAddress:"e2e@imas.invalid", password:$pw, status:"active", roles:["imas-read"]}')" >/dev/null
for v in "$v1" "$v2"; do
	nexus POST "/v1/components?repository=imas-apt" -F "apt.asset=@$work/pkg/imas-sprout_${v}_linux_amd64.deb"
	nexus POST "/v1/components?repository=imas-yum" -F "yum.asset=@$work/pkg/imas-sprout_${v}_linux_amd64.rpm" \
		-F "yum.asset.filename=imas-sprout_${v}_linux_amd64.rpm" -F "yum.directory=Packages"
done
echo "published: $(ls "$work/pkg" | tr '\n' ' ')"
# Nexus rebuilds repository metadata on a delay (about a minute for yum).
for path in imas-apt/dists/any/InRelease imas-yum/repodata/repomd.xml; do
	for _ in $(seq 1 60); do
		[[ "$(curl -s --noproxy '*' -u "admin:$nexus_pw" -o /dev/null -w '%{http_code}' "http://127.0.0.1:$nexus_port/repository/$path")" == 200 ]] && break
		sleep 5
	done
	echo "metadata ready: $path"
done

# --- 5-7. Per distro ------------------------------------------------------
sprout_exec() { docker exec "e2e-sprout-$1" sh -ec "$2"; }

installed_version() { # distro
	if [[ $1 == debian ]]; then
		sprout_exec "$1" "dpkg-query -W -f='\${Version}' imas-sprout"
	else
		sprout_exec "$1" "rpm -q --qf '%{VERSION}' imas-sprout"
	fi
}

main_pid() { sprout_exec "$1" 'systemctl show -p MainPID --value imas-sprout'; }

# cook.CompletionStatus values (internal/cook/cooktypes.go).
step_completed=2
step_failed=3

# job_step JID: the selfupdate step's event, once it has arrived.
job_step() {
	farmer GET /_stub/fleet | jq -c --arg j "$1" '(.events[$j] // [])[] | select(.ID | startswith("selfupdate-"))'
}

wait_step() { # JID -> prints the step event
	local ev=""
	for _ in $(seq 1 90); do
		ev="$(job_step "$1")"
		[[ -n "$ev" ]] && break
		sleep 2
	done
	echo "$ev"
}

# selfupdate SPROUT VERSION -> job ID
selfupdate() {
	farmer POST /_stub/selfupdate "{\"sprout_id\":\"$1\",\"version\":\"$2\"}" | jq -r .job_id
}

release() { # VERSION PKGTYPE FILE SHA256 [SIGNER]
	farmer POST /_stub/release "$(jq -n --arg v "v$1" --arg t "$2" --arg f "$3" --arg s "$4" --arg signer "${5:-trusted}" \
		'{version:$v, os:"linux", arch:"amd64", package_type:$t, file_name:$f, checksum_sha256:$s, min_sprout_version:"v0.1.0", signer:$signer}')" >/dev/null
}

expect_refusal() { # distro sprout version want-substring description
	local jid ev
	jid="$(selfupdate "$2" "v$3")"
	ev="$(wait_step "$jid")"
	if [[ "$(jq -r .CompletionStatus <<<"$ev")" == "$step_failed" ]] && grep -qi -- "$4" <<<"$(jq -r '.Error // ""' <<<"$ev")"; then
		ok "$5: refused ($(jq -r .Error <<<"$ev"))"
	else
		bad "$5: got $ev"
	fi
	[[ "$(installed_version "$1")" == "$v2" ]] && ok "$5: imas-sprout is still $v2" || bad "$5: installed version changed"
}

for distro in $distros; do
	image="${sprout_image[$distro]}"
	pkg=deb
	[[ $distro == rocky ]] && pkg=rpm
	sprout="sprout-$distro"
	log "[$distro] Preparing a systemd sprout host ($image)"
	if ! docker image inspect "$image" >/dev/null 2>&1 && ! docker pull -q "$image" >/dev/null 2>&1; then
		bad "[$distro] could not pull $image; skipped"
		continue
	fi
	docker run -d --name "e2e-sprout-$distro" --hostname "$sprout" --network "$net" --privileged --cgroupns=host \
		-v /sys/fs/cgroup:/sys/fs/cgroup:rw -v "$work:/work:ro" "$image" /usr/lib/systemd/systemd >/dev/null
	for _ in $(seq 1 30); do sprout_exec "$distro" 'systemctl is-system-running' 2>/dev/null | grep -qE 'running|degraded' && break; sleep 1; done

	# The repository's CA goes in the OS trust store (the self-update
	# download uses it); the farmer's CA only in SproutRootCA.
	if [[ $distro == debian ]]; then
		sprout_exec "$distro" '
			cp /work/state/repo-ca.pem /usr/local/share/ca-certificates/imas-e2e-repo.crt
			update-ca-certificates >/dev/null
			rm -f /etc/apt/sources.list.d/* /etc/apt/sources.list
			install -d -m 0755 /etc/apt/keyrings
			cp /work/gpg/public.asc /etc/apt/keyrings/imas-e2e.asc
			echo "deb [signed-by=/etc/apt/keyrings/imas-e2e.asc] https://repo:8443/repository/imas-apt/ any main" > /etc/apt/sources.list.d/imas.list
			printf "machine repo:8443/repository/imas-apt\nlogin buildkite\npassword '"$repo_token"'\n" > /etc/apt/auth.conf.d/imas.conf
			chmod 0600 /etc/apt/auth.conf.d/imas.conf
			apt-get update -qq
			DEBIAN_FRONTEND=noninteractive apt-get install -qq -y imas-sprout='"$v1"' >/dev/null'
		repo_url="https://repo:8443/repository/imas-apt/"
	else
		sprout_exec "$distro" '
			cp /work/state/repo-ca.pem /etc/pki/ca-trust/source/anchors/imas-e2e-repo.pem
			update-ca-trust
			rm -f /etc/yum.repos.d/*.repo
			printf "[imas-e2e]\nname=imas e2e\nbaseurl=https://repo:8443/repository/imas-yum/\nenabled=1\ngpgcheck=0\nrepo_gpgcheck=0\nusername=buildkite\npassword='"$repo_token"'\n" > /etc/yum.repos.d/imas-e2e.repo
			chmod 0600 /etc/yum.repos.d/imas-e2e.repo
			dnf -q -y install imas-sprout-'"$v1"' >/dev/null'
		repo_url="https://repo:8443/repository/imas-yum/"
	fi
	[[ "$(installed_version "$distro")" == "$v1" ]] && ok "[$distro] imas-sprout $v1 installed from Nexus by the OS package manager" ||
		bad "[$distro] imas-sprout $v1 not installed"

	sprout_exec "$distro" '
		install -d -m 0755 /etc/imas/pki/sprout
		cp /work/state/ca.pem /etc/imas/pki/sprout/tls-rootca.pem
		cat > /etc/imas/sprout <<EOF
farmerinterface: farmer
farmerapiport: 5405
sproutrootcatofu: false
jointoken: '"$join_token"'
sproutupdaterepourl: '"$repo_url"'
sproutupdaterepotoken: '"$repo_token"'
loglevel: info
EOF
		chmod 0600 /etc/imas/sprout
		systemctl start imas-sprout'
	for _ in $(seq 1 60); do
		[[ "$(farmer GET /_stub/fleet | jq -r --arg s "$sprout" '.announces[$s] // ""')" == "v$v1" ]] && break
		sleep 2
	done
	[[ "$(farmer GET /_stub/fleet | jq -r --arg s "$sprout" '.announces[$s] // ""')" == "v$v1" ]] &&
		ok "[$distro] the sprout enrolled, connected and announced v$v1" ||
		{ bad "[$distro] the sprout did not connect"; sprout_exec "$distro" 'journalctl -u imas-sprout --no-pager | tail -40'; continue; }

	log "[$distro] Self-update to v$v2"
	file="imas-sprout_${v2}_linux_amd64.$pkg"
	release "$v2" "$pkg" "$file" "$(sha256sum "$work/pkg/$file" | cut -d' ' -f1)"
	pid_before="$(main_pid "$distro")"
	proxy_mark="$(docker logs e2e-farmer 2>&1 | wc -l)"
	jid="$(selfupdate "$sprout" "v$v2")"
	ev="$(wait_step "$jid")"
	if [[ "$(jq -r .CompletionStatus <<<"$ev")" == "$step_completed" ]]; then
		ok "[$distro] the self_update job succeeded"
		jq -r '.Changes[]? // empty' <<<"$ev" | sed 's/^/      note: /'
	else
		bad "[$distro] the self_update job failed: $ev"
		sprout_exec "$distro" 'journalctl -u imas-sprout --no-pager | tail -40'
		continue
	fi
	# Wait for the restart onto the new binary (10s after the job reported)
	# and its announcement; the stale v$v1 announcement doesn't count.
	for _ in $(seq 1 60); do
		[[ "$(main_pid "$distro")" != "$pid_before" ]] &&
			[[ "$(farmer GET /_stub/fleet | jq -r --arg s "$sprout" '.announces[$s] // ""')" == "v$v2" ]] && break
		sleep 2
	done
	[[ "$(installed_version "$distro")" == "$v2" ]] && ok "[$distro] imas-sprout $v2 is installed" || bad "[$distro] installed: $(installed_version "$distro")"
	pid_after="$(main_pid "$distro")"
	[[ "$pid_after" != 0 && "$pid_after" != "$pid_before" ]] && ok "[$distro] the service restarted (MainPID $pid_before -> $pid_after)" ||
		bad "[$distro] the service did not restart (MainPID $pid_before -> $pid_after)"
	running_sha="$(sprout_exec "$distro" "sha256sum /proc/$pid_after/exe" | cut -d' ' -f1)"
	[[ "$running_sha" == "$(sha256sum "$work/bin/imas-sprout-$v2" | cut -d' ' -f1)" ]] &&
		ok "[$distro] the running process is the v$v2 binary" || bad "[$distro] the running binary is not v$v2"
	[[ "$(farmer GET /_stub/fleet | jq -r --arg s "$sprout" '.announces[$s] // ""')" == "v$v2" ]] &&
		ok "[$distro] the sprout reconnected and announced v$v2" || bad "[$distro] no v$v2 announcement"
	# What reached the repository during the update: only the sprout's
	# index and package requests, each with the repo token, never the JWT.
	repo_auth="$(docker logs e2e-farmer 2>&1 | tail -n +"$((proxy_mark + 1))" | grep -o 'repo: GET [^ ]* (auth: [^)]*)' || true)"
	echo "$repo_auth" | sed 's/^/      /'
	if [[ -n "$repo_auth" ]] && ! grep -v 'auth: basic:buildkite' <<<"$repo_auth" | grep -q .; then
		ok "[$distro] every repository request carried the repo token (basic, user buildkite), none the JWT"
	else
		bad "[$distro] repository requests with other credentials"
	fi

	log "[$distro] Refusals"
	expect_refusal "$distro" "$sprout" "$v1" "downgrade" "[$distro] downgrade to v$v1"
	release 0.3.0 "$pkg" "imas-sprout_0.3.0_linux_amd64.$pkg" "$(sha256sum "$work/pkg/$file" | cut -d' ' -f1)" untrusted
	expect_refusal "$distro" "$sprout" 0.3.0 "signature" "[$distro] manifest signed by an untrusted key"
	release 0.4.0 "$pkg" "imas-sprout_0.4.0_linux_amd64.$pkg" "$(printf '%064d' 0)"
	expect_refusal "$distro" "$sprout" 0.4.0 "not in the update repository" "[$distro] checksum not in the repository"
	expect_refusal "$distro" "$sprout" 0.9.0 "no update manifest" "[$distro] version with no manifest"
done

log "Result: $pass passed, $fail failed"
[[ $fail == 0 ]]

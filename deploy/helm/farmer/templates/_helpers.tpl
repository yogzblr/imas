{{/*
Naming.
*/}}
{{- define "imas-farmer.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "imas-farmer.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "imas-farmer.saasapi.fullname" -}}
{{- printf "%s-saasapi" (include "imas-farmer.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "imas-farmer.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Labels. Both workloads share app.kubernetes.io/name (the nats chart's bus
NetworkPolicy admits core by it); "component" keeps their selectors apart.
*/}}
{{- define "imas-farmer.labels" -}}
helm.sh/chart: {{ include "imas-farmer.chart" . }}
app.kubernetes.io/name: {{ include "imas-farmer.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: imas
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{- define "imas-farmer.farmer.selectorLabels" -}}
app.kubernetes.io/name: {{ include "imas-farmer.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: farmer
{{- end }}

{{- define "imas-farmer.saasapi.selectorLabels" -}}
app.kubernetes.io/name: {{ include "imas-farmer.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: saasapi
{{- end }}

{{/*
The publish Job's pods keep the reference's own name label
(deploy/farmer/saasapi-credential-publish-job.yaml), deliberately not the
chart's: the nats chart's bus NetworkPolicy admits core by
app.kubernetes.io/name, and this Job must never reach the bus.
*/}}
{{- define "imas-farmer.publisher.selectorLabels" -}}
app.kubernetes.io/name: imas-saasapi-cred-publisher
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
The migrate Job's pods. Their own name label, like the publisher's: the
nats chart's bus NetworkPolicy admits core by app.kubernetes.io/name, and
a pod holding PXC's root password must never reach the bus.
*/}}
{{- define "imas-farmer.migrate.selectorLabels" -}}
app.kubernetes.io/name: imas-migrate
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: db-migrate
{{- end }}

{{/* Short enough that "<prefix>-db-migrate-check" fits 63 characters
and stays distinct from "<prefix>-db-migrate". */}}
{{- define "imas-farmer.migrate.namePrefix" -}}
{{- include "imas-farmer.fullname" . | trunc 46 | trimSuffix "-" -}}
{{- end }}

{{/*
The Secret holding PXC root's password for the migrate Job's root step,
or "" when the step is skipped (`migrate up --skip-root`):
database.migrate.rootPasswordSecret if set; else, with the bundled PXC,
the operator's <cluster>-secrets (or pxc.pxc.clusterSecretName); else
nothing, and the external PXC's schemas, users and grants are ops' job.
*/}}
{{- define "imas-farmer.migrate.rootSecret" -}}
{{- $m := .Values.database.migrate -}}
{{- if $m.rootPasswordSecret -}}
{{- $m.rootPasswordSecret -}}
{{- else if .Values.pxc.enabled -}}
{{- default (printf "%s-secrets" (include "imas-farmer.pxc.clusterName" .)) .Values.pxc.pxc.clusterSecretName -}}
{{- end -}}
{{- end }}

{{- define "imas-farmer.farmer.serviceAccountName" -}}
{{- if .Values.farmer.serviceAccount.create }}
{{- default (include "imas-farmer.fullname" .) .Values.farmer.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.farmer.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "imas-farmer.saasapi.serviceAccountName" -}}
{{- if .Values.saasapi.serviceAccount.create }}
{{- default (include "imas-farmer.saasapi.fullname" .) .Values.saasapi.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.saasapi.serviceAccount.name }}
{{- end }}
{{- end }}

{{/* image reference: repository[:tag][@digest] */}}
{{- define "imas-farmer.image" -}}
{{- $img := .image -}}
{{- if $img.digest -}}
{{- printf "%s@%s" $img.repository $img.digest -}}
{{- else -}}
{{- printf "%s:%s" $img.repository (toString (default .appVersion $img.tag)) -}}
{{- end -}}
{{- end }}

{{- define "imas-farmer.farmer.image" -}}
{{- include "imas-farmer.image" (dict "image" .Values.farmer.image "appVersion" .Chart.AppVersion) -}}
{{- end }}

{{/* In-cluster FQDN of the farmer API Service. */}}
{{- define "imas-farmer.farmer.serviceFQDN" -}}
{{- printf "%s.%s.svc.%s" (include "imas-farmer.fullname" .) .Release.Namespace .Values.clusterDomain }}
{{- end }}

{{/*
The bus Service FQDN, "<svc>.<ns>.svc.<domain>", and the URL farmer
(farmerbusurl) and saasapi (SAASAPI_NATS_URL) dial it at. The nats chart's
default certificate SANs cover the FQDN (deploy/helm/nats,
imas-nats.bus.defaultCertHosts), and it is what both processes verify the
bus certificate against unless bus.tlsServerName says otherwise.
*/}}
{{- define "imas-farmer.busFQDN" -}}
{{- printf "%s.%s.svc.%s" .Values.bus.serviceName .Values.bus.namespace .Values.clusterDomain }}
{{- end }}

{{- define "imas-farmer.busURL" -}}
{{- printf "tls://%s:%v" (include "imas-farmer.busFQDN" .) .Values.bus.port }}
{{- end }}

{{/*
Subchart Service names, mirroring each subchart's own fullname helper
(openbao.fullname, pxc-database.fullname, valkey.fullname) so they track
nameOverride/fullnameOverride set under the subchart's key.
*/}}
{{- define "imas-farmer.subchartFullname" -}}
{{- $v := .values -}}
{{- $trunc := int (default 63 .trunc) -}}
{{- if $v.fullnameOverride -}}
{{- $v.fullnameOverride | trunc $trunc | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .chart $v.nameOverride -}}
{{- if contains $name .release -}}
{{- .release | trunc $trunc | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .release $name | trunc $trunc | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end }}

{{- define "imas-farmer.openbao.fullname" -}}
{{- include "imas-farmer.subchartFullname" (dict "values" .Values.openbao "chart" "openbao" "release" .Release.Name) -}}
{{- end }}

{{/* pxc-db truncates its fullname (the cluster name) to 21 characters. */}}
{{- define "imas-farmer.pxc.clusterName" -}}
{{- include "imas-farmer.subchartFullname" (dict "values" .Values.pxc "chart" "pxc" "release" .Release.Name "trunc" 21) -}}
{{- end }}

{{- define "imas-farmer.valkey.fullname" -}}
{{- include "imas-farmer.subchartFullname" (dict "values" .Values.valkey "chart" "valkey" "release" .Release.Name) -}}
{{- end }}

{{/* OpenBao address every imas client uses. */}}
{{- define "imas-farmer.openbaoAddr" -}}
{{- if .Values.openbaoClient.addr -}}
{{- .Values.openbaoClient.addr -}}
{{- else if .Values.openbao.enabled -}}
{{- printf "http://%s.%s.svc.%s:8200" (include "imas-farmer.openbao.fullname" .) .Release.Namespace .Values.clusterDomain -}}
{{- end -}}
{{- end }}

{{/* PXC host both DSNs use. */}}
{{- define "imas-farmer.dbHost" -}}
{{- if .Values.database.host -}}
{{- .Values.database.host -}}
{{- else if .Values.pxc.enabled -}}
{{- printf "%s-haproxy.%s.svc.%s" (include "imas-farmer.pxc.clusterName" .) .Release.Namespace .Values.clusterDomain -}}
{{- end -}}
{{- end }}

{{/* Secret holding both DSNs. */}}
{{- define "imas-farmer.dbSecretName" -}}
{{- default (printf "%s-db" (include "imas-farmer.fullname" .)) .Values.database.existingSecret -}}
{{- end }}

{{/* Comma-separated Valkey host:port list, for both services. */}}
{{- define "imas-farmer.valkeyAddrs" -}}
{{- if .Values.valkey.enabled -}}
{{- printf "%s.%s.svc.%s:6379" (include "imas-farmer.valkey.fullname" .) .Release.Namespace .Values.clusterDomain -}}
{{- else -}}
{{- join "," (default (list) .Values.valkey.addrs) -}}
{{- end -}}
{{- end }}

{{/*
Seeds: natsSeeds.seeds merged with natsSeeds.extraSeeds, as a dict of
NAME -> secret key. Output is YAML so callers can fromYaml it.
*/}}
{{- define "imas-farmer.seeds" -}}
{{- $all := merge (dict) (deepCopy (default (dict) .Values.natsSeeds.extraSeeds)) (deepCopy (default (dict) .Values.natsSeeds.seeds)) -}}
{{- toYaml $all -}}
{{- end }}

{{/* farmer's TLS file paths inside the container, per tls.mode. */}}
{{- define "imas-farmer.tlsDir" -}}
{{- if eq .Values.tls.mode "secret" -}}
/etc/imas/tls
{{- else -}}
/var/run/imas/tls
{{- end -}}
{{- end }}

{{/* SANs for farmer's own certificate: its Service's names. */}}
{{- define "imas-farmer.defaultCertHosts" -}}
{{- $svc := include "imas-farmer.fullname" . -}}
{{- $ns := .Release.Namespace -}}
{{- toYaml (list $svc (printf "%s.%s" $svc $ns) (printf "%s.%s.svc" $svc $ns) (printf "%s.%s.svc.%s" $svc $ns .Values.clusterDomain)) -}}
{{- end }}

{{/*
OpenBao env block for one client. Call with (dict "root" $ "prefix"
"IMAS_GATEWAY_OPENBAO" "k8sRole" <role> "tokenKey" <key>), plus an optional
"tokenSecret" overriding openbaoClient.tokenSecretName. Every client
gets its own role; the shared parts are address, CA and auth method.
*/}}
{{- define "imas-farmer.openbaoEnv" -}}
{{- $c := .root.Values.openbaoClient -}}
- name: {{ .prefix }}_ADDR
  value: {{ include "imas-farmer.openbaoAddr" .root | quote }}
- name: {{ .prefix }}_AUTH_METHOD
  value: {{ $c.authMethod | quote }}
{{- if $c.caConfigMap }}
- name: {{ .prefix }}_CACERT
  value: /var/run/secrets/openbao-ca/{{ $c.caKey }}
{{- end }}
{{- if eq $c.authMethod "kubernetes" }}
- name: {{ .prefix }}_K8S_ROLE
  value: {{ .k8sRole | quote }}
- name: {{ .prefix }}_K8S_MOUNT
  value: {{ $c.k8sMount | quote }}
- name: {{ .prefix }}_K8S_JWT_PATH
  value: /var/run/secrets/openbao-auth/token
{{- else }}
- name: {{ .prefix }}_TOKEN
  valueFrom:
    secretKeyRef:
      name: {{ default $c.tokenSecretName .tokenSecret }}
      key: {{ .tokenKey }}
{{- end }}
{{- end }}

{{/* OpenBao auth/CA volumes, for any pod running an OpenBao client. */}}
{{- define "imas-farmer.openbaoVolumes" -}}
{{- $c := .Values.openbaoClient -}}
{{- if eq $c.authMethod "kubernetes" }}
- name: openbao-auth
  projected:
    sources:
      - serviceAccountToken:
          path: token
          audience: {{ $c.k8sAudience | quote }}
          expirationSeconds: 600
{{- end }}
{{- if $c.caConfigMap }}
- name: openbao-ca
  configMap:
    name: {{ $c.caConfigMap }}
{{- end }}
{{- end }}

{{- define "imas-farmer.openbaoVolumeMounts" -}}
{{- $c := .Values.openbaoClient -}}
{{- if eq $c.authMethod "kubernetes" }}
- name: openbao-auth
  mountPath: /var/run/secrets/openbao-auth
  readOnly: true
{{- end }}
{{- if $c.caConfigMap }}
- name: openbao-ca
  mountPath: /var/run/secrets/openbao-ca
  readOnly: true
{{- end }}
{{- end }}

{{/*
One egress rule, as a one-item YAML list, to a dependency on one port.
Bundled: this namespace's pods. External: networkPolicy.external.<dep>
(empty = any destination, on that port only). Call with
(dict "bundled" <bool> "peers" <list> "port" <int>).
*/}}
{{- define "imas-farmer.depEgress" -}}
{{- $rule := dict "ports" (list (dict "protocol" "TCP" "port" (int .port))) -}}
{{- if .bundled -}}
{{- $_ := set $rule "to" (list (dict "podSelector" (dict))) -}}
{{- else if .peers -}}
{{- $_ := set $rule "to" .peers -}}
{{- end -}}
{{- toYaml (list $rule) -}}
{{- end }}

{{- define "imas-farmer.dnsEgress" -}}
- to:
    - namespaceSelector:
        {{- toYaml .Values.networkPolicy.dns.namespaceSelector | nindent 8 }}
      podSelector:
        {{- toYaml .Values.networkPolicy.dns.podSelector | nindent 8 }}
  ports:
    - { protocol: UDP, port: 53 }
    - { protocol: TCP, port: 53 }
{{- end }}

{{- define "imas-farmer.openbaoEgress" -}}
{{- include "imas-farmer.depEgress" (dict "bundled" .Values.openbao.enabled "peers" .Values.networkPolicy.external.openbao "port" .Values.networkPolicy.external.openbaoPort) -}}
{{- end }}

{{/*
True (non-empty) when saasapi fetches the bus CA from OpenBao PKI: no
explicit bus.ca source, and the CA lives in OpenBao (tls.mode=openbao).
*/}}
{{- define "imas-farmer.saasapi.fetchCA" -}}
{{- if and (not .Values.bus.ca.secretName) (not .Values.bus.ca.configMapName) (eq .Values.tls.mode "openbao") -}}true{{- end -}}
{{- end }}

{{/* True (non-empty) when saasapi runs its read-only fleet key client
(IMAS_FLEETSIGN_OPENBAO_*): fleet dispatch and the operator plane each
refuse to start without it. */}}
{{- define "imas-farmer.saasapi.fleetVerify" -}}
{{- if and .Values.saasapi.enabled (or .Values.saasapi.fleetUpdateDispatch.enabled .Values.saasapi.operator.enabled) -}}true{{- end -}}
{{- end }}

{{/* True (non-empty) when saasapi talks to OpenBao at all: the fleet key
client, or the bus CA fetch. */}}
{{- define "imas-farmer.saasapi.needsOpenBao" -}}
{{- if or (include "imas-farmer.saasapi.fleetVerify" .) (include "imas-farmer.saasapi.fetchCA" .) -}}true{{- end -}}
{{- end }}

{{/*
saasapi's operator plane (internal/saasapi NewOperatorServer, API design
§2.5): its own Service, never the one the gateway routes to.
*/}}
{{- define "imas-farmer.saasapi.operatorFullname" -}}
{{- printf "%s-operator" (include "imas-farmer.saasapi.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "imas-farmer.saasapi.operatorFQDN" -}}
{{- printf "%s.%s.svc.%s" (include "imas-farmer.saasapi.operatorFullname" .) .Release.Namespace .Values.clusterDomain }}
{{- end }}

{{/* The port in saasapi.operator.fleetReleaser.url (443 when it has none),
for saasapi's egress rule. */}}
{{- define "imas-farmer.saasapi.fleetReleaserPort" -}}
{{- $host := (urlParse .Values.saasapi.operator.fleetReleaser.url).host -}}
{{- default "443" (regexFind ":[0-9]+$" $host | trimPrefix ":") -}}
{{- end }}

{{/* The port in objectStore.endpoint (host[:port], no scheme; with none,
443 under useSSL, else 80), for saasapi's recipe egress rule. */}}
{{- define "imas-farmer.objectStorePort" -}}
{{- $def := ternary "443" "80" (ne (toString .Values.objectStore.useSSL) "false") -}}
{{- default $def (regexFind ":[0-9]+$" (toString .Values.objectStore.endpoint) | trimPrefix ":") -}}
{{- end }}

{{/*
The sprout release this chart carries: files/sprout-release.json, written
at release time by packaging/helm/stamp-sprout-release.sh and absent from a
source checkout. "" when absent.
*/}}
{{- define "imas-farmer.sproutRelease.file" -}}
{{- .Files.Get "files/sprout-release.json" -}}
{{- end }}

{{/* True (non-empty) when the registration hook Job renders: the chart
carries a sprout release, registration is on, and this release runs
saasapi with its operator plane. */}}
{{- define "imas-farmer.sproutRelease.registers" -}}
{{- if and (include "imas-farmer.sproutRelease.file" .) .Values.sproutRelease.register .Values.saasapi.enabled .Values.saasapi.operator.enabled -}}true{{- end -}}
{{- end }}

{{/*
The registration Job's pods. Their own name label, like the publisher's:
the nats chart's bus NetworkPolicy admits core by app.kubernetes.io/name,
and a pod holding the operator token must never reach the bus.
*/}}
{{- define "imas-farmer.registrar.selectorLabels" -}}
app.kubernetes.io/name: imas-sprout-release-registrar
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: sprout-release-registrar
{{- end }}

{{/*
The request body for POST /v1/operator/fleet-releases: the stamped
release (version, min_sprout_version, packages; both versions set at
release time) plus this chart's channel, validated here so a bad value
fails the render rather than the hook. saasapi validates every package
field again, and never normalizes; neither does this.
*/}}
{{- define "imas-farmer.sproutRelease.request" -}}
{{- $r := .Values.sproutRelease -}}
{{- $rel := include "imas-farmer.sproutRelease.file" . | fromJson -}}
{{- if or (hasKey $rel "Error") (not (kindIs "map" $rel)) -}}
{{- fail (printf "files/sprout-release.json is not a JSON object: %v" (get $rel "Error")) -}}
{{- end -}}
{{- range $k, $_ := $rel -}}
{{- if not (has $k (list "version" "min_sprout_version" "packages")) -}}
{{- fail (printf "files/sprout-release.json has an unexpected field %q: it holds exactly version, min_sprout_version and packages (packaging/helm/stamp-sprout-release.sh)" $k) -}}
{{- end -}}
{{- end -}}
{{- $semver := "^v(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\\.[0-9A-Za-z-]+)*)?$" -}}
{{- $version := toString (get $rel "version") -}}
{{- if not (regexMatch $semver $version) -}}
{{- fail (printf "files/sprout-release.json version %q is not a canonical vMAJOR.MINOR.PATCH[-PRERELEASE] version; re-stamp it with packaging/helm/stamp-sprout-release.sh (saasapi refuses anything else, and nothing here rewrites it)" $version) -}}
{{- end -}}
{{- if ne $version (printf "v%s" .Chart.AppVersion) -}}
{{- fail (printf "files/sprout-release.json is sprout release %s, but this chart is appVersion %s: the farmer chart and the sprout release it registers ship under one tag (docs/RELEASING.md)" $version .Chart.AppVersion) -}}
{{- end -}}
{{- $pkgs := get $rel "packages" -}}
{{- if or (not (kindIs "slice" $pkgs)) (not $pkgs) -}}
{{- fail "files/sprout-release.json has no packages" -}}
{{- end -}}
{{- $min := toString (get $rel "min_sprout_version") -}}
{{- if not (regexMatch $semver $min) -}}
{{- fail (printf "files/sprout-release.json min_sprout_version %q is missing or not a canonical vMAJOR.MINOR.PATCH[-PRERELEASE] version; re-stamp it (packaging/helm/min-sprout-version)" $min) -}}
{{- end -}}
{{- if gt ((semver $min).Compare (semver $version)) 0 -}}
{{- fail (printf "files/sprout-release.json min_sprout_version %s is above the release's version %s" $min $version) -}}
{{- end -}}
{{- if not (regexMatch "^[a-z][a-z0-9_-]{0,31}$" (toString $r.channel)) -}}
{{- fail (printf "sproutRelease.channel %q must match ^[a-z][a-z0-9_-]{0,31}$" (toString $r.channel)) -}}
{{- end -}}
{{- toPrettyJson (dict "version" $version "channel" $r.channel "min_sprout_version" $min "packages" $pkgs) -}}
{{- end }}

{{/*
The OpenBao policies the bootstrap Job writes. The three reviewed ones
are verbatim copies checked by chart_test.go against their sources; the
farmer-only ones are rendered here from the values they name.
*/}}
{{- define "imas-farmer.policy.farmerGateway" -}}
{{- $g := .Values.farmer.openbao.gateway -}}
# imas-farmer-gateway: farmer's gateway JWT signer (internal/gatewayjwt).
# Exact paths only. A "*" or "+" under transit/sign would also reach
# imas-fleet-signing (deploy/fleetreleaser/README.md).
path "{{ $g.transitMount }}/sign/{{ $g.keyName }}" {
  capabilities = ["update"]
}

path "{{ $g.transitMount }}/keys/{{ $g.keyName }}" {
  capabilities = ["read"]
}
{{- end }}

{{- define "imas-farmer.policy.farmerCerts" -}}
# imas-farmer-certs: farmer's API certificate (internal/certs). Issue from
# one PKI role; the CA itself is read unauthenticated.
path "{{ .Values.tls.openbao.pkiMount }}/issue/{{ .Values.tls.openbao.role }}" {
  capabilities = ["update"]
}
{{- end }}

{{- define "imas-farmer.policy.farmerTenantBox" -}}
{{- $t := .Values.farmer.openbao.tenantBox -}}
# imas-farmer-tenantbox: tenant X25519 keypairs (internal/pki
# tenantbox.go). KV v2 read and write on one secret per tenant under
# <kvPath>/tenants/ ("+" matches exactly one path segment: a tenant ID,
# nothing deeper), and nothing else: no access to <kvPath> itself (the
# shared legacy keypair and its adoption are gone, security review
# 2026-10 H3), and no metadata, delete or destroy.
path "{{ $t.kvMount }}/data/{{ $t.kvPath }}/tenants/+" {
  capabilities = ["create", "update", "read"]
}

# The platform keypair and the control-plane public keys (internal/pki
# platformbox.go, J.1): read only. The keygen Job creates them; farmer
# never writes either, and never reads <kvPath>/saasapi-box, the SaaS
# API's private key.
path "{{ $t.kvMount }}/data/{{ $t.kvPath }}/platform" {
  capabilities = ["read"]
}

path "{{ $t.kvMount }}/data/{{ $t.kvPath }}/controlplane-pub" {
  capabilities = ["read"]
}
{{- end }}

{{- define "imas-farmer.policy.controlPlaneBoxKeygen" -}}
{{- $t := .Values.farmer.openbao.tenantBox -}}
# imas-controlplane-box-keygen: `farmer ensure-controlplane-box-keys`
# (internal/pki controlplanekeys.go, J.1). Create and read the platform
# and SaaS API keypairs, never update them, so no run can replace a key;
# create, read and update the public halves it publishes. Nothing under
# <kvPath>/tenants/, and no metadata, delete or destroy.
path "{{ $t.kvMount }}/data/{{ $t.kvPath }}/platform" {
  capabilities = ["create", "read"]
}

path "{{ $t.kvMount }}/data/{{ $t.kvPath }}/saasapi-box" {
  capabilities = ["create", "read"]
}

path "{{ $t.kvMount }}/data/{{ $t.kvPath }}/controlplane-pub" {
  capabilities = ["create", "read", "update"]
}
{{- end }}

{{- define "imas-farmer.policy.farmerbusCerts" -}}
# imas-farmerbus-certs: the nats chart's bus certificate in openbao mode.
path "{{ .Values.tls.openbao.pkiMount }}/issue/imas-farmerbus" {
  capabilities = ["update"]
}
{{- end }}

{{/*
Render-time validation. Everything here fails the render with an
explanation rather than deploying something that silently can't work.
*/}}
{{- define "imas-farmer.validate" -}}
{{- if hasKey .Values "postgresql" -}}
{{- fail "postgresql.* is not a value of this chart: imas's farmer and saas schemas live in one PXC (Percona XtraDB Cluster), not Postgres (docs/design/cloudxp-machine-manager-api-design.md). The bundled database toggle is pxc.enabled; an external one is database.host/existingSecret." -}}
{{- end -}}
{{- if not (regexMatch "^[0-9A-Za-z_-]{1,191}$" (toString .Values.organization)) -}}
{{- fail (printf "organization %q is not a valid tenant ID (^[0-9A-Za-z_-]{1,191}$, internal/pki IsValidTenantID); it is farmerorganization and must equal the nats chart's bus.organization" .Values.organization) -}}
{{- end -}}
{{- if .Values.farmer.adminPubKeys -}}
{{- fail "farmer.adminPubKeys was removed in J.3: every imas CLI request is sealed with the user's CLI box key, so an admin listed by NKey alone can't make a single request. Set farmer.bootstrapAdmin.pubkey and farmer.bootstrapAdmin.boxpub (from the admin's imas auth keygen) instead." -}}
{{- end -}}
{{- with .Values.farmer.bootstrapAdmin -}}
{{- if or .pubkey .boxpub .username -}}
{{- if not (regexMatch "^A[A-Z2-7]{55}$" (toString .pubkey)) -}}
{{- fail (printf "farmer.bootstrapAdmin.pubkey %q is not an NKey user public key (imas auth pubkey prints it: A and 55 more base32 characters)" (toString .pubkey)) -}}
{{- end -}}
{{- if not (regexMatch "^[A-Za-z0-9+/]{43}=$" (toString .boxpub)) -}}
{{- fail "farmer.bootstrapAdmin.boxpub is required with pubkey: the CLI box public key (standard base64, 32 bytes) the admin's imas auth keygen printed. Without it the first admin can't make a request." -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if not .Values.bus.serviceName -}}
{{- fail "bus.serviceName is required: the nats chart's bus client Service (<release>-nats-bus), with bus.namespace its namespace" -}}
{{- end -}}
{{- if not .Values.bus.namespace -}}
{{- fail "bus.namespace is required" -}}
{{- end -}}
{{- if not .Values.bus.sproutBusURLs -}}
{{- fail "bus.sproutBusURLs is required (IMAS_SPROUT_BUS_URLS): the nats chart's Envoy wss:// address(es). Without it farmer hands enrolling sprouts an in-cluster bus address they can't reach." -}}
{{- end -}}
{{- range .Values.bus.sproutBusURLs -}}
{{- if not (hasPrefix "wss://" (toString .)) -}}
{{- fail (printf "bus.sproutBusURLs entry %q must be a wss:// URL (sprouts reach the bus only through Envoy's websocket route)" .) -}}
{{- end -}}
{{- end -}}
{{- with .Values.bus.tlsServerName -}}
{{- if not (regexMatch "^[A-Za-z0-9]([-A-Za-z0-9.]*[A-Za-z0-9])?$" (toString .)) -}}
{{- fail (printf "bus.tlsServerName %q must be a DNS name (farmerbustlsservername is a TLS ServerName, not a URL or host:port)" .) -}}
{{- end -}}
{{- end -}}
{{- if and .Values.bus.ca.secretName .Values.bus.ca.configMapName -}}
{{- fail "set only one of bus.ca.secretName and bus.ca.configMapName" -}}
{{- end -}}
{{- if not .Values.natsSeeds.secretName -}}
{{- fail "natsSeeds.secretName is required: this chart never generates NATS seeds. Point it at the Secret ESO syncs from OpenBao (externalSecrets, or deploy/farmer/externalsecrets.yaml)." -}}
{{- end -}}
{{- $seeds := fromYaml (include "imas-farmer.seeds" .) -}}
{{- range $name := list "OPERATOR" "OPERATOR_SIGNING" "SYS_ACCOUNT" "TENANT" "TENANT_SIGNING" "SAASAPI_USER" -}}
{{- if not (get $seeds $name) -}}
{{- fail (printf "natsSeeds.seeds.%s is required. Without it farmer generates its own %s seed on its PVC, which splits it from the bus's trust chain or from saasapi's credential (see README.md, \"Seeds\")." $name $name) -}}
{{- end -}}
{{- end -}}
{{- range $name, $key := $seeds -}}
{{- if not (regexMatch "^[A-Z0-9_]+$" $name) -}}
{{- fail (printf "natsSeeds seed name %q must match ^[A-Z0-9_]+$ (it becomes IMAS_NATS_%s_SEED_FILE)" $name $name) -}}
{{- end -}}
{{- if not (regexMatch "^[-._a-zA-Z0-9]+$" (toString $key)) -}}
{{- fail (printf "natsSeeds seed %s: secret key %q is not a valid Secret key" $name $key) -}}
{{- end -}}
{{- end -}}
{{- if not (has .Values.tls.mode (list "secret" "openbao")) -}}
{{- fail (printf "tls.mode must be \"secret\" or \"openbao\", got %q" .Values.tls.mode) -}}
{{- end -}}
{{- if and (eq .Values.tls.mode "secret") (not .Values.tls.secretName) -}}
{{- fail "tls.secretName is required when tls.mode=secret" -}}
{{- end -}}
{{- include "imas-farmer.saasapiBox.validate" . -}}
{{- if not (include "imas-farmer.openbaoAddr" .) -}}
{{- fail "openbaoClient.addr is required when openbao.enabled=false (farmer's gateway signer, fleet key source, tenant box and the publish Job all need OpenBao)" -}}
{{- end -}}
{{- if not (has .Values.openbaoClient.authMethod (list "kubernetes" "token")) -}}
{{- fail "openbaoClient.authMethod must be \"kubernetes\" or \"token\"" -}}
{{- end -}}
{{- if and (eq .Values.openbaoClient.authMethod "token") (not .Values.openbaoClient.tokenSecretName) -}}
{{- fail "openbaoClient.tokenSecretName is required when authMethod=token" -}}
{{- end -}}
{{- if not (include "imas-farmer.dbHost" .) -}}
{{- fail "database.host is required when pxc.enabled=false" -}}
{{- end -}}
{{- if hasKey .Values.database "bootstrap" -}}
{{- fail "database.bootstrap.* was replaced by database.migrate.* (the cmd/migrate hook Job, docs/design/cloudxp-machine-manager-api-design.md §4.1a): rootPasswordSecret, rootPasswordKey, activeDeadlineSeconds and resources moved there. There is no enabled toggle: farmer and saasapi no longer migrate their own schemas." -}}
{{- end -}}
{{- $mig := .Values.database.migrate -}}
{{- if not (regexMatch "^[1-9][0-9]*(s|m|h)$" (toString $mig.wait)) -}}
{{- fail (printf "database.migrate.wait %q must be a whole number of s, m or h, such as \"15m\"" (toString $mig.wait)) -}}
{{- end -}}
{{- if not (regexMatch "^[A-Za-z0-9_.-]{1,32}$" (toString $mig.rootUser)) -}}
{{- fail (printf "database.migrate.rootUser %q is not a MySQL user name" (toString $mig.rootUser)) -}}
{{- end -}}
{{- if and .Values.pxc.enabled (not .Values.database.existingSecret) -}}
{{- $db := .Values.database -}}
{{- range $v := list $db.farmer.name $db.farmer.user $db.saasapi.name $db.saasapi.user -}}
{{- if not (regexMatch "^[A-Za-z0-9_]{1,32}$" (toString $v)) -}}
{{- fail (printf "database schema/user name %q must match ^[A-Za-z0-9_]{1,32}$ (it goes into the generated DSNs, and cmd/migrate writes it into DDL)" $v) -}}
{{- end -}}
{{- end -}}
{{- if or (eq (toString $db.farmer.name) (toString $db.saasapi.name)) (eq (toString $db.farmer.user) (toString $db.saasapi.user)) -}}
{{- fail "database.farmer and database.saasapi must name different schemas and different users: single writer per schema (§4.1)" -}}
{{- end -}}
{{- end -}}
{{- if and (not .Values.pxc.enabled) (not .Values.database.existingSecret) -}}
{{- fail "database.existingSecret is required when pxc.enabled=false: an existing Secret with farmer's and saasapi's full DSNs (database.existingSecretKeys). The chart only generates credentials for the PXC it deploys." -}}
{{- end -}}
{{- if ne (int .Values.farmer.replicaCount) 1 -}}
{{- fail "farmer.replicaCount must be 1: FarmerPKI (NATS JWTs, the SaaS API credential's rotation state, farmer's NKey) lives on one ReadWriteOnce volume, and a second replica would mint and push from a divergent copy. See README.md, \"Why one farmer replica\"." -}}
{{- end -}}
{{- with .Values.farmer.jobs.reconcileWindow -}}
{{- if not (kindIs "string" .) -}}
{{- fail (printf "farmer.jobs.reconcileWindow must be a quoted duration such as \"2h\", got %v" .) -}}
{{- end -}}
{{- end -}}
{{- $tl := .Values.farmer.recipes.templateLimits -}}
{{- range $k := list "maxSourceBytes" "maxRenderedBytes" "maxValueBytes" "maxRangeIterations" -}}
{{- $v := get $tl $k -}}
{{- if not (or (kindIs "float64" $v) (kindIs "int64" $v) (kindIs "int" $v)) -}}
{{- fail (printf "farmer.recipes.templateLimits.%s must be a positive whole number, got %v" $k $v) -}}
{{- end -}}
{{- if or (lt (float64 $v) 1.0) (ne (float64 $v) (float64 (int64 $v))) -}}
{{- fail (printf "farmer.recipes.templateLimits.%s must be a positive whole number, got %v" $k $v) -}}
{{- end -}}
{{- end -}}
{{- if not (and (kindIs "string" $tl.renderTimeout) (regexMatch "^[0-9]+(\\.[0-9]+)?(ms|s|m)$" (toString $tl.renderTimeout))) -}}
{{- fail (printf "farmer.recipes.templateLimits.renderTimeout must be a quoted duration such as \"2s\", got %v" $tl.renderTimeout) -}}
{{- end -}}
{{- $os := .Values.objectStore -}}
{{- if and $os.bucket $os.jobBucket (eq $os.bucket $os.jobBucket) -}}
{{- fail "objectStore.jobBucket must differ from objectStore.bucket: GET /files/ serves every key in the recipe bucket to any authenticated caller, so job logs there would be readable across sprouts and tenants" -}}
{{- end -}}
{{- if .Values.saasapi.enabled -}}
{{- include "imas-farmer.saasapi.validate" . -}}
{{- end -}}
{{- if .Values.credentialPublisher.enabled -}}
{{- include "imas-farmer.publisher.validate" . -}}
{{- end -}}
{{- if .Values.controlPlaneBoxKeys.enabled -}}
{{- include "imas-farmer.cpbox.validate" . -}}
{{- end -}}
{{- if hasKey .Values.sproutRelease "minSproutVersion" -}}
{{- fail "sproutRelease.minSproutVersion was removed: min_sprout_version is set at release time, from packaging/helm/min-sprout-version, and stamped into files/sprout-release.json with the version" -}}
{{- end -}}
{{- if include "imas-farmer.sproutRelease.registers" . -}}
{{- include "imas-farmer.registrar.validate" . -}}
{{- end -}}
{{- end }}

{{- define "imas-farmer.saasapi.validate" -}}
{{- $s := .Values.saasapi -}}
{{- range $k := list "keycloakJWKSURL" "issuer" "audience" -}}
{{- if not (get $s.jwt $k) -}}
{{- fail (printf "saasapi.jwt.%s is required: saasapi refuses to start without the Keycloak JWKS URL, issuer and audience" $k) -}}
{{- end -}}
{{- end -}}
{{- if not $s.internalAuthSecret.secretName -}}
{{- fail "saasapi.internalAuthSecret.secretName is required (INTERNAL_AUTH_SECRET_CURRENT)" -}}
{{- end -}}
{{- if not $s.natsCredentials.secretName -}}
{{- fail "saasapi.natsCredentials.secretName is required: saasapi's NATS seed and JWT (externalSecrets.saasapi renders it)" -}}
{{- end -}}
{{- with $s.enrollmentKeys.rateLimit -}}
{{- if and (not (kindIs "invalid" .burst)) (ne (float64 .burst) (float64 (int .burst))) -}}
{{- fail (printf "saasapi.enrollmentKeys.rateLimit.burst must be a whole number, got %v" .burst) -}}
{{- end -}}
{{- end -}}
{{- if lt (int $s.replicaCount) 1 -}}
{{- fail "saasapi.replicaCount must be at least 1" -}}
{{- end -}}
{{- include "imas-farmer.saasapi.recipes.validate" . -}}
{{- if $s.operator.enabled -}}
{{- include "imas-farmer.saasapi.operator.validate" . -}}
{{- end -}}
{{- end }}

{{- define "imas-farmer.saasapi.recipes.validate" -}}
{{- $r := .Values.saasapi.recipes -}}
{{- if or (not $r.readRole) (not $r.writeRole) (eq (toString $r.readRole) (toString $r.writeRole)) -}}
{{- fail "saasapi.recipes.readRole and writeRole must both be set and differ: one role for both would make every reader a recipe writer" -}}
{{- end -}}
{{- range $k := list "maxCount" "maxTotalBytes" -}}
{{- $v := get $r $k -}}
{{- if not (or (kindIs "float64" $v) (kindIs "int64" $v) (kindIs "int" $v)) -}}
{{- fail (printf "saasapi.recipes.%s must be a positive whole number, got %v" $k $v) -}}
{{- end -}}
{{- if or (lt (float64 $v) 1.0) (ne (float64 $v) (float64 (int64 $v))) -}}
{{- fail (printf "saasapi.recipes.%s must be a positive whole number, got %v" $k $v) -}}
{{- end -}}
{{- end -}}
{{- $b := $r.writeRateLimit.burst -}}
{{- if or (kindIs "invalid" $b) (lt (float64 $b) 1.0) (ne (float64 $b) (float64 (int $b))) -}}
{{- fail (printf "saasapi.recipes.writeRateLimit.burst must be a whole number >= 1, got %v" $b) -}}
{{- end -}}
{{- if $r.enabled -}}
{{- if not $r.credentialsSecret -}}
{{- fail "saasapi.recipes.credentialsSecret is required with saasapi.recipes.enabled: saasapi's OWN object-store access key pair, limited to tenants/*/recipes/* (files/objectstore-policies/)" -}}
{{- end -}}
{{- if eq (toString $r.credentialsSecret) (toString .Values.objectStore.credentialsSecret) -}}
{{- fail "saasapi.recipes.credentialsSecret must not be objectStore.credentialsSecret: farmer's credential can write sprouts/ and the platform recipe prefix, saasapi's must only reach tenants/*/recipes/*" -}}
{{- end -}}
{{- if or (not .Values.objectStore.endpoint) (not .Values.objectStore.bucket) -}}
{{- fail "saasapi.recipes.enabled needs objectStore.endpoint and objectStore.bucket: saasapi writes the bucket farmer cooks from" -}}
{{- end -}}
{{- end -}}
{{- end }}

{{- define "imas-farmer.saasapi.operator.validate" -}}
{{- $s := .Values.saasapi -}}
{{- $o := $s.operator -}}
{{- if not $o.tls.secretName -}}
{{- fail (printf "saasapi.operator.tls.secretName is required with saasapi.operator.enabled: a kubernetes.io/tls Secret (tls.crt, tls.key, and the ca.crt the registration Job verifies it with) for %s" (include "imas-farmer.saasapi.operatorFQDN" .)) -}}
{{- end -}}
{{- if not $o.token.secretName -}}
{{- fail "saasapi.operator.token.secretName is required with saasapi.operator.enabled: the Secret holding the operator bearer token (SAASAPI_OPERATOR_TOKEN_FILE)" -}}
{{- end -}}
{{- if and $o.token.previousKey (eq (toString $o.token.previousKey) (toString $o.token.currentKey)) -}}
{{- fail "saasapi.operator.token.previousKey must differ from currentKey" -}}
{{- end -}}
{{- range $other := list $s.internalAuthSecret.secretName $s.natsCredentials.secretName $o.fleetReleaser.tokenSecretName $o.tls.secretName .Values.natsSeeds.secretName -}}
{{- if eq (toString $o.token.secretName) (toString $other) -}}
{{- fail (printf "saasapi.operator.token.secretName %q must be a Secret of its own: the registration Job mounts it, and must never be able to mount another credential with it (saasapi also refuses an operator token equal to the BFF's or its fleetreleaser token)" $o.token.secretName) -}}
{{- end -}}
{{- end -}}
{{- if not (regexMatch "^https://[^/?#@]+/?$" (toString $o.fleetReleaser.url)) -}}
{{- fail (printf "saasapi.operator.fleetReleaser.url %q must be https://host[:port], no path, query or credentials (SAASAPI_FLEETRELEASER_URL): cmd/fleetreleaser, the only signer" (toString $o.fleetReleaser.url)) -}}
{{- end -}}
{{- if not $o.fleetReleaser.tokenSecretName -}}
{{- fail "saasapi.operator.fleetReleaser.tokenSecretName is required with saasapi.operator.enabled (SAASAPI_FLEETRELEASER_TOKEN_FILE)" -}}
{{- end -}}
{{- if eq (int $o.port) (int $s.port) -}}
{{- fail "saasapi.operator.port must differ from saasapi.port: the operator plane is its own listener" -}}
{{- end -}}
{{- end }}

{{- define "imas-farmer.registrar.validate" -}}
{{- $r := .Values.sproutRelease -}}
{{- if hasKey $r "image" -}}
{{- fail "sproutRelease.image was removed: the hook runs `farmer register-sprout-release` in farmer's own image (farmer.image)" -}}
{{- end -}}
{{- $_ := include "imas-farmer.sproutRelease.request" . -}}
{{- if not (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$" (toString $r.serviceAccountName)) -}}
{{- fail (printf "sproutRelease.serviceAccountName %q is not a valid ServiceAccount name" (toString $r.serviceAccountName)) -}}
{{- end -}}
{{- range $sa := list (include "imas-farmer.farmer.serviceAccountName" .) (include "imas-farmer.saasapi.serviceAccountName" .) .Values.credentialPublisher.serviceAccountName -}}
{{- if eq (toString $r.serviceAccountName) $sa -}}
{{- fail (printf "sproutRelease.serviceAccountName %q is another workload's ServiceAccount: the registration Job gets one of its own, with no RBAC and no OpenBao role" $sa) -}}
{{- end -}}
{{- end -}}
{{- range $k := list "attempts" "initialDelaySeconds" "maxDelaySeconds" -}}
{{- if lt (int (get $r.retry $k)) 1 -}}
{{- fail (printf "sproutRelease.retry.%s must be at least 1" $k) -}}
{{- end -}}
{{- end -}}
{{- if lt (int $r.requestTimeoutSeconds) 1 -}}
{{- fail "sproutRelease.requestTimeoutSeconds must be at least 1" -}}
{{- end -}}
{{- end }}

{{- define "imas-farmer.publisher.validate" -}}
{{- $p := .Values.credentialPublisher -}}
{{- if not $p.kvPath -}}
{{- fail "credentialPublisher.kvPath is required: it is the path the publisher's OpenBao policy is scoped to (IMAS_SAASAPI_CRED_OPENBAO_KV_PATH has no default)" -}}
{{- end -}}
{{- $pub := trimAll "/" $p.kvPath -}}
{{- $seed := trimAll "/" .Values.externalSecrets.seedPath -}}
{{- if or (eq $pub $seed) (hasPrefix (printf "%s/" $seed) $pub) (hasPrefix (printf "%s/" $pub) $seed) -}}
{{- fail (printf "credentialPublisher.kvPath %q and externalSecrets.seedPath %q must be different, and neither may be a prefix of the other: the publisher's write policy must never reach a seed" $p.kvPath .Values.externalSecrets.seedPath) -}}
{{- end -}}
{{- if eq $p.serviceAccountName (include "imas-farmer.farmer.serviceAccountName" .) -}}
{{- fail "credentialPublisher.serviceAccountName must not be farmer's ServiceAccount: that token is the KV-write credential, and farmer's long-running process must never hold it" -}}
{{- end -}}
{{- if and .Values.saasapi.enabled (eq $p.serviceAccountName (include "imas-farmer.saasapi.serviceAccountName" .)) -}}
{{- fail "credentialPublisher.serviceAccountName must not be saasapi's ServiceAccount" -}}
{{- end -}}
{{- range $r := list .Values.tls.openbao.k8sRole .Values.farmer.openbao.gateway.k8sRole .Values.farmer.openbao.fleetSign.k8sRole .Values.farmer.openbao.tenantBox.k8sRole -}}
{{- if eq $r $p.k8sRole -}}
{{- fail (printf "credentialPublisher.k8sRole %q is also one of farmer's OpenBao roles: the KV-write role must never be one farmer can log in with" $p.k8sRole) -}}
{{- end -}}
{{- end -}}
{{- end }}

{{/*
saasapi's box key Secret (saasapi.controlPlaneBox, J.4). It holds the
SaaS API's PRIVATE box key, so it must be a Secret of its own: never one
farmer, the publish Job or the bus mounts, so no other workload's pod can
read it. With ESO, it is read through the same SecretStore as the other
ExternalSecrets, so the tenant box KV mount must be that store's mount
(credentialPublisher.kvMount's).
*/}}
{{- define "imas-farmer.saasapiBox.validate" -}}
{{- if .Values.saasapi.enabled -}}
{{- $b := .Values.saasapi.controlPlaneBox -}}
{{- if not (regexMatch "^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$" (toString $b.secretName)) -}}
{{- fail (printf "saasapi.controlPlaneBox.secretName %q is not a valid Secret name" (toString $b.secretName)) -}}
{{- end -}}
{{- $others := list .Values.natsSeeds.secretName .Values.saasapi.natsCredentials.secretName (include "imas-farmer.dbSecretName" .) .Values.saasapi.internalAuthSecret.secretName -}}
{{- if eq .Values.tls.mode "secret" -}}
{{- $others = append $others .Values.tls.secretName -}}
{{- end -}}
{{- if has $b.secretName $others -}}
{{- fail (printf "saasapi.controlPlaneBox.secretName %q is another Secret this chart mounts: it holds the SaaS API's private box key and must be its own, mounted only in saasapi's pods" $b.secretName) -}}
{{- end -}}
{{- range $k := list $b.privKey $b.platformPubKey -}}
{{- if not (regexMatch "^[-._a-zA-Z0-9]+$" (toString $k)) -}}
{{- fail (printf "saasapi.controlPlaneBox: secret key %q is not a valid Secret key" (toString $k)) -}}
{{- end -}}
{{- end -}}
{{- if eq (toString $b.privKey) (toString $b.platformPubKey) -}}
{{- fail "saasapi.controlPlaneBox.privKey and platformPubKey must differ" -}}
{{- end -}}
{{- if and .Values.externalSecrets.enabled .Values.externalSecrets.saasapi.enabled (ne .Values.farmer.openbao.tenantBox.kvMount .Values.credentialPublisher.kvMount) -}}
{{- fail (printf "farmer.openbao.tenantBox.kvMount %q must equal credentialPublisher.kvMount %q with externalSecrets on: saasapi's box key (<tenantBox.kvPath>/saasapi-box) is read through the same SecretStore as its NATS JWT" .Values.farmer.openbao.tenantBox.kvMount .Values.credentialPublisher.kvMount) -}}
{{- end -}}
{{- end -}}
{{- end }}

{{/*
The control-plane keygen Job's identity is its own: never farmer's,
saasapi's or the publisher's ServiceAccount or OpenBao role. Its token can
create the platform key and the SaaS API's private key.
*/}}
{{- define "imas-farmer.cpbox.validate" -}}
{{- $c := .Values.controlPlaneBoxKeys -}}
{{- $sas := list (include "imas-farmer.farmer.serviceAccountName" .) .Values.credentialPublisher.serviceAccountName -}}
{{- if .Values.saasapi.enabled -}}
{{- $sas = append $sas (include "imas-farmer.saasapi.serviceAccountName" .) -}}
{{- end -}}
{{- if has $c.serviceAccountName $sas -}}
{{- fail (printf "controlPlaneBoxKeys.serviceAccountName %q is another workload's ServiceAccount: the keygen Job's token can create the platform key and the SaaS API's private key, so it must be its own" $c.serviceAccountName) -}}
{{- end -}}
{{- range $r := list .Values.tls.openbao.k8sRole .Values.farmer.openbao.gateway.k8sRole .Values.farmer.openbao.fleetSign.k8sRole .Values.farmer.openbao.tenantBox.k8sRole .Values.credentialPublisher.k8sRole .Values.saasapi.openbao.fleetSign.k8sRole -}}
{{- if eq $r $c.k8sRole -}}
{{- fail (printf "controlPlaneBoxKeys.k8sRole %q is another workload's OpenBao role" $c.k8sRole) -}}
{{- end -}}
{{- end -}}
{{- end }}

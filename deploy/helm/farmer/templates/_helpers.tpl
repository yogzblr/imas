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

{{/* True (non-empty) when saasapi talks to OpenBao at all: fleet
dispatch's verify client, or the bus CA fetch. */}}
{{- define "imas-farmer.saasapi.needsOpenBao" -}}
{{- if or .Values.saasapi.fleetUpdateDispatch.enabled (include "imas-farmer.saasapi.fetchCA" .) -}}true{{- end -}}
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
# nothing deeper), and read-only on <kvPath> itself, the legacy
# one-per-deployment keypair that tenants with already-enrolled sprouts
# adopt on first use. No metadata, delete or destroy.
path "{{ $t.kvMount }}/data/{{ $t.kvPath }}" {
  capabilities = ["read"]
}

path "{{ $t.kvMount }}/data/{{ $t.kvPath }}/tenants/+" {
  capabilities = ["create", "update", "read"]
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

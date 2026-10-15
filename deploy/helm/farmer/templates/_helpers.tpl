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
bus.host, when set, replaces the FQDN: a bus outside this cluster, whose
certificate must then carry bus.host.
*/}}
{{- define "imas-farmer.busFQDN" -}}
{{- if .Values.bus.host -}}
{{- .Values.bus.host }}
{{- else -}}
{{- printf "%s.%s.svc.%s" .Values.bus.serviceName .Values.bus.namespace .Values.clusterDomain }}
{{- end -}}
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

{{/*
The bus egress rule of farmer's and saasapi's NetworkPolicies, as a
one-item YAML list, on bus.port. Peers: the nats chart's bus pods
(networkPolicy.dmz), plus an ipBlock per bus.egressCIDRs entry. With
bus.host and bus.egressCIDRs both set, only the ipBlocks: the selector
can't match a bus outside the cluster. With bus.host alone the selector
stays, so the rule matches nothing outside the cluster (README.md,
"Reaching the bus") rather than turning into "any destination".
*/}}
{{- define "imas-farmer.busEgress" -}}
- to:
    {{- if or (not .Values.bus.host) (not .Values.bus.egressCIDRs) }}
    - namespaceSelector:
        {{- toYaml .Values.networkPolicy.dmz.namespaceSelector | nindent 8 }}
      podSelector:
        {{- toYaml .Values.networkPolicy.dmz.busPodSelector | nindent 8 }}
    {{- end }}
    {{- range .Values.bus.egressCIDRs }}
    - ipBlock:
        cidr: {{ . | quote }}
    {{- end }}
  ports:
    - { protocol: TCP, port: {{ .Values.bus.port }} }
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

{{/*
The Versity Gateway (versity.enabled; design D18): the S3 front of Azure
Blob. Its Service is the default S3 endpoint of farmer, saasapi and the
accounts bucket: objectStore.endpoint and accountStore.endpoint, when
empty, mean the gateway, and either still overrides it.
*/}}
{{- define "imas-farmer.versity.fullname" -}}
{{- printf "%s-versity" (include "imas-farmer.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Its pods' own name label, like the publisher's: the nats chart's bus
NetworkPolicy admits core by app.kubernetes.io/name, and the gateway never
dials the bus. */}}
{{- define "imas-farmer.versity.selectorLabels" -}}
app.kubernetes.io/name: imas-versity
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: versity
{{- end }}

{{- define "imas-farmer.versity.bucketsSelectorLabels" -}}
app.kubernetes.io/name: imas-versity
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: versity-buckets
{{- end }}

{{- define "imas-farmer.versity.image" -}}
{{- include "imas-farmer.image" (dict "image" .Values.versity.image "appVersion" "") -}}
{{- end }}

{{/* host:port of the gateway's Service. */}}
{{- define "imas-farmer.versity.endpoint" -}}
{{- printf "%s.%s.svc.%s:%v" (include "imas-farmer.versity.fullname" .) .Release.Namespace .Values.clusterDomain .Values.versity.port -}}
{{- end }}

{{/* True (non-empty) when the recipe, job and sprout JWT buckets are the
gateway's: versity.enabled and objectStore.endpoint left empty. */}}
{{- define "imas-farmer.s3UsesVersity" -}}
{{- if and .Values.versity.enabled (not .Values.objectStore.endpoint) -}}true{{- end -}}
{{- end }}

{{/* True (non-empty) when the accounts bucket is the gateway's: neither
accountStore.endpoint nor objectStore.endpoint set, versity.enabled. */}}
{{- define "imas-farmer.accountsUseVersity" -}}
{{- if and (include "imas-farmer.s3UsesVersity" .) (not .Values.accountStore.endpoint) -}}true{{- end -}}
{{- end }}

{{/* The S3 endpoint farmer (IMAS_S3_ENDPOINT) and saasapi's recipe
upload use: objectStore.endpoint, or the gateway's Service. */}}
{{- define "imas-farmer.s3Endpoint" -}}
{{- if include "imas-farmer.s3UsesVersity" . -}}
{{- include "imas-farmer.versity.endpoint" . -}}
{{- else -}}
{{- .Values.objectStore.endpoint -}}
{{- end -}}
{{- end }}

{{/* "true" or "false": objectStore.useSSL, or false for the gateway's
Service (plain HTTP inside the cluster; README.md, "Versity Gateway"). */}}
{{- define "imas-farmer.s3UseSSL" -}}
{{- if include "imas-farmer.s3UsesVersity" . -}}false{{- else -}}{{ ne (toString .Values.objectStore.useSSL) "false" }}{{- end -}}
{{- end }}

{{/* The port in the S3 endpoint (host[:port], no scheme; with none, 443
under useSSL, else 80), for farmer's object store egress rule and
saasapi's recipe egress rule. */}}
{{- define "imas-farmer.objectStorePort" -}}
{{- $def := ternary "443" "80" (eq (include "imas-farmer.s3UseSSL" .) "true") -}}
{{- default $def (regexFind ":[0-9]+$" (include "imas-farmer.s3Endpoint" .) | trimPrefix ":") -}}
{{- end }}

{{/* The port of the accounts bucket's endpoint, as objectStorePort, for
farmer's egress rule when accountStore.endpoint is its own. */}}
{{- define "imas-farmer.accountStorePort" -}}
{{- $acc := .Values.accountStore -}}
{{- $ssl := ternary (include "imas-farmer.s3UseSSL" .) (toString $acc.useSSL) (kindIs "invalid" $acc.useSSL) -}}
{{- $def := ternary "443" "80" (ne $ssl "false") -}}
{{- default $def (regexFind ":[0-9]+$" (toString (default (include "imas-farmer.s3Endpoint" .) $acc.endpoint)) | trimPrefix ":") -}}
{{- end }}

{{/* The egress peers of the object store rules: the gateway's pods when
the store is the gateway (s3UsesVersity), else
networkPolicy.external.objectStore. .versity selects which. */}}
{{- define "imas-farmer.objectStorePeers" -}}
{{- if .versity -}}
{{- toYaml (list (dict "podSelector" (dict "matchLabels" (fromYaml (include "imas-farmer.versity.selectorLabels" .root))))) -}}
{{- else if .root.Values.networkPolicy.external.objectStore -}}
{{- toYaml .root.Values.networkPolicy.external.objectStore -}}
{{- end -}}
{{- end }}

{{/*
The gateway's users (versitysetup readUsers): name -> the Secret and keys
its credential comes from. farmer (objectStore.credentialsSecret: the
recipe, job and sprout JWT buckets) and saasapi-recipes (with
saasapi.recipes.enabled) when the S3 store is the gateway; the accounts
writer (accountStore.credentialsSecret) and the DMZ bus's accounts reader
(versity.accountsReader) when the accounts bucket is.
*/}}
{{- define "imas-farmer.versity.users" -}}
{{- $u := dict -}}
{{- $os := .Values.objectStore -}}
{{- if include "imas-farmer.s3UsesVersity" . -}}
{{- $_ := set $u "farmer" (dict "secret" $os.credentialsSecret "id" $os.accessKeyIdKey "key" $os.secretAccessKeyKey "value" "objectStore.credentialsSecret") -}}
{{- $r := .Values.saasapi.recipes -}}
{{- if and .Values.saasapi.enabled $r.enabled -}}
{{- $_ := set $u "saasapi-recipes" (dict "secret" $r.credentialsSecret "id" $r.accessKeyIdKey "key" $r.secretAccessKeyKey "value" "saasapi.recipes.credentialsSecret") -}}
{{- end -}}
{{- end -}}
{{- if include "imas-farmer.accountsUseVersity" . -}}
{{- $acc := .Values.accountStore -}}
{{- $_ := set $u "accounts-writer" (dict "secret" $acc.credentialsSecret "id" $acc.accessKeyIdKey "key" $acc.secretAccessKeyKey "value" "accountStore.credentialsSecret") -}}
{{- $rd := .Values.versity.accountsReader -}}
{{- $_ := set $u "accounts-reader" (dict "secret" $rd.credentialsSecret "id" $rd.accessKeyIdKey "key" $rd.secretAccessKeyKey "value" "versity.accountsReader.credentialsSecret") -}}
{{- end -}}
{{- toYaml $u -}}
{{- end }}

{{/* The projected volume of the gateway's users: <user>/access-key-id
and, with .secrets, <user>/secret-access-key. */}}
{{- define "imas-farmer.versity.usersVolume" -}}
{{- $users := fromYaml (include "imas-farmer.versity.users" .root) -}}
projected:
  defaultMode: 0440
  sources:
    {{- range $name := keys $users | sortAlpha }}
    {{- $c := get $users $name }}
    - secret:
        name: {{ $c.secret }}
        items:
          - { key: {{ $c.id }}, path: {{ $name }}/access-key-id }
          {{- if $.secrets }}
          - { key: {{ $c.key }}, path: {{ $name }}/secret-access-key }
          {{- end }}
    {{- end }}
{{- end }}

{{/* The root credential's projected volume (access-key-id, and with
.secrets secret-access-key). */}}
{{- define "imas-farmer.versity.rootVolume" -}}
{{- $r := .root.Values.versity.rootCredentials -}}
projected:
  defaultMode: 0440
  sources:
    - secret:
        name: {{ $r.secretName }}
        items:
          - { key: {{ $r.accessKeyIdKey }}, path: access-key-id }
          {{- if .secrets }}
          - { key: {{ $r.secretAccessKeyKey }}, path: secret-access-key }
          {{- end }}
{{- end }}

{{/*
The createBuckets plan (internal/versitysetup Plan): each bucket the
gateway serves and the Allow statements of its policy, per user, scoped to
that bucket as in design D22 and the UAT's RustFS policies
(uat/hub/core/rustfs-setup.sh). saasapi's statements are
files/objectstore-policies/saasapi-recipes.json, the same reviewed policy.
*/}}
{{- define "imas-farmer.versity.plan" -}}
{{- $os := .Values.objectStore -}}
{{- $buckets := list -}}
{{- if include "imas-farmer.s3UsesVersity" . -}}
{{- $listS := list "s3:GetBucketLocation" "s3:ListBucket" -}}
{{- $rw := list "s3:GetObject" "s3:PutObject" "s3:DeleteObject" -}}
{{- $recipes := list
  (dict "sid" "FarmerBucket" "user" "farmer" "actions" $listS "resources" (list (printf "arn:aws:s3:::%s" $os.bucket)))
  (dict "sid" "FarmerObjects" "user" "farmer" "actions" $rw "resources" (list (printf "arn:aws:s3:::%s/*" $os.bucket))) -}}
{{- $r := .Values.saasapi.recipes -}}
{{- if and .Values.saasapi.enabled $r.enabled -}}
{{- $pol := .Files.Get "files/objectstore-policies/saasapi-recipes.json" | replace "RECIPE_BUCKET" (toString $os.bucket) | fromJson -}}
{{- range $pol.Statement -}}
{{- $st := dict "sid" (printf "Saasapi%s" .Sid) "user" "saasapi-recipes" "actions" .Action "resources" .Resource -}}
{{- with .Condition -}}
{{- $_ := set $st "condition" . -}}
{{- end -}}
{{- $recipes = append $recipes $st -}}
{{- end -}}
{{- end -}}
{{- $buckets = append $buckets (dict "name" $os.bucket "statements" $recipes) -}}
{{- $buckets = append $buckets (dict "name" $os.jobBucket "statements" (list
  (dict "sid" "FarmerBucket" "user" "farmer" "actions" $listS "resources" (list (printf "arn:aws:s3:::%s" $os.jobBucket)))
  (dict "sid" "FarmerObjects" "user" "farmer" "actions" $rw "resources" (list (printf "arn:aws:s3:::%s/*" $os.jobBucket))))) -}}
{{- $buckets = append $buckets (dict "name" $os.sproutJWTBucket "statements" (list
  (dict "sid" "FarmerBucket" "user" "farmer" "actions" $listS "resources" (list (printf "arn:aws:s3:::%s" $os.sproutJWTBucket)))
  (dict "sid" "FarmerSproutJWTs" "user" "farmer" "actions" (list "s3:GetObject" "s3:PutObject") "resources" (list (printf "arn:aws:s3:::%s/*" $os.sproutJWTBucket))))) -}}
{{- end -}}
{{- if include "imas-farmer.accountsUseVersity" . -}}
{{- $b := .Values.accountStore.bucket -}}
{{- $listS := list "s3:GetBucketLocation" "s3:ListBucket" -}}
{{- /* farmer writes accounts/<pub>.jwt and accounts/index and never
deletes (a deprovision is a newer lock-out JWT); the loader only reads. */ -}}
{{- $buckets = append $buckets (dict "name" $b "statements" (list
  (dict "sid" "AccountsWriterBucket" "user" "accounts-writer" "actions" $listS "resources" (list (printf "arn:aws:s3:::%s" $b)))
  (dict "sid" "AccountsWriterObjects" "user" "accounts-writer" "actions" (list "s3:GetObject" "s3:PutObject") "resources" (list (printf "arn:aws:s3:::%s/*" $b)))
  (dict "sid" "AccountsReaderBucket" "user" "accounts-reader" "actions" $listS "resources" (list (printf "arn:aws:s3:::%s" $b)))
  (dict "sid" "AccountsReaderObjects" "user" "accounts-reader" "actions" (list "s3:GetObject") "resources" (list (printf "arn:aws:s3:::%s/*" $b))))) -}}
{{- end -}}
{{- dict "buckets" $buckets | toPrettyJson -}}
{{- end }}

{{/*
versity.enabled: the gateway's settings and every credential and bucket it
serves. Called from imas-farmer.validate.
*/}}
{{- define "imas-farmer.versity.validate" -}}
{{- $v := .Values.versity -}}
{{- if not (include "imas-farmer.s3UsesVersity" .) -}}
{{- fail "versity.enabled with objectStore.endpoint set: the gateway would serve no bucket. Leave objectStore.endpoint (and accountStore.endpoint) empty to use the gateway, or turn versity.enabled off to use another S3 endpoint" -}}
{{- end -}}
{{- if not (regexMatch "^sha256:[0-9a-f]{64}$" (toString $v.image.digest)) -}}
{{- fail "versity.image.digest must be the image's sha256 digest (sha256:<64 hex>): the gateway image is pinned by digest" -}}
{{- end -}}
{{- if not (and (kindIs "float64" $v.replicas) (ge (float64 $v.replicas) 1.0) (eq (float64 $v.replicas) (float64 (int64 $v.replicas)))) -}}
{{- if not (and (or (kindIs "int64" $v.replicas) (kindIs "int" $v.replicas)) (ge (int64 $v.replicas) 1)) -}}
{{- fail (printf "versity.replicas must be a whole number, 1 or more, got %v" $v.replicas) -}}
{{- end -}}
{{- end -}}
{{- $az := $v.azure -}}
{{- if not $az.credentialsSecret -}}
{{- fail "versity.azure.credentialsSecret is required with versity.enabled: the Secret holding the Azure storage account name and key the gateway stores the buckets in (README.md, \"Versity Gateway\")" -}}
{{- end -}}
{{- if or (not $az.accountNameKey) (not $az.accountKeyKey) -}}
{{- fail "versity.azure.accountNameKey and versity.azure.accountKeyKey are required with versity.enabled" -}}
{{- end -}}
{{- if and $az.endpoint (not (regexMatch "^https://[^/\\s]+/?$" (toString $az.endpoint))) -}}
{{- fail (printf "versity.azure.endpoint must be an https:// Blob service URL with no path, got %q" $az.endpoint) -}}
{{- end -}}
{{- $root := $v.rootCredentials -}}
{{- if not $root.secretName -}}
{{- fail "versity.rootCredentials.secretName is required with versity.enabled: the gateway's root S3 credential, which only the gateway and the createBuckets Job hold" -}}
{{- end -}}
{{- if or (not $root.accessKeyIdKey) (not $root.secretAccessKeyKey) -}}
{{- fail "versity.rootCredentials.accessKeyIdKey and secretAccessKeyKey are required with versity.enabled" -}}
{{- end -}}
{{- $users := fromYaml (include "imas-farmer.versity.users" .) -}}
{{- $seen := dict -}}
{{- range $name := keys $users | sortAlpha -}}
{{- $c := get $users $name -}}
{{- if not $c.secret -}}
{{- fail (printf "%s is required with versity.enabled: the gateway's %s user is created from it" $c.value $name) -}}
{{- end -}}
{{- if or (not $c.id) (not $c.key) -}}
{{- fail (printf "the access key ID and secret key names of %s are required with versity.enabled" $c.value) -}}
{{- end -}}
{{- if eq (toString $c.secret) (toString $root.secretName) -}}
{{- fail (printf "%s must not be versity.rootCredentials.secretName: the root credential belongs to the gateway and the createBuckets Job alone" $c.value) -}}
{{- end -}}
{{- if hasKey $seen (toString $c.secret) -}}
{{- fail (printf "%s and %s are the same Secret: every gateway user needs a credential of its own, scoped to its own buckets (design D22)" (get $seen (toString $c.secret)) $c.value) -}}
{{- end -}}
{{- $_ := set $seen (toString $c.secret) $c.value -}}
{{- end -}}
{{- if eq (toString $az.credentialsSecret) (toString $root.secretName) -}}
{{- fail "versity.azure.credentialsSecret must not be versity.rootCredentials.secretName" -}}
{{- end -}}
{{- if hasKey $seen (toString $az.credentialsSecret) -}}
{{- fail (printf "versity.azure.credentialsSecret must not be %s: the Azure account key belongs to the gateway alone" (get $seen (toString $az.credentialsSecret))) -}}
{{- end -}}
{{- $os := .Values.objectStore -}}
{{- $names := dict "objectStore.bucket" $os.bucket "objectStore.jobBucket" $os.jobBucket "objectStore.sproutJWTBucket" $os.sproutJWTBucket -}}
{{- if include "imas-farmer.accountsUseVersity" . -}}
{{- $_ := set $names "accountStore.bucket" .Values.accountStore.bucket -}}
{{- end -}}
{{- range $k := keys $names | sortAlpha -}}
{{- $b := toString (get $names $k) -}}
{{- if not $b -}}
{{- fail (printf "%s is required with versity.enabled: the createBuckets Job creates it on the gateway" $k) -}}
{{- end -}}
{{- if or (not (regexMatch "^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$" $b)) (contains "--" $b) -}}
{{- fail (printf "%s %q is not a bucket name Azure Blob takes as a container name: 3 to 63 of a-z 0-9 and -, no leading, trailing or double hyphen" $k $b) -}}
{{- end -}}
{{- end -}}
{{- $sa := toString $v.createBuckets.serviceAccountName -}}
{{- if not (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$" $sa) -}}
{{- fail (printf "versity.createBuckets.serviceAccountName %q is not a valid ServiceAccount name" $sa) -}}
{{- end -}}
{{- range $other := list (include "imas-farmer.farmer.serviceAccountName" .) (include "imas-farmer.saasapi.serviceAccountName" .) .Values.credentialPublisher.serviceAccountName .Values.controlPlaneBoxKeys.serviceAccountName .Values.sproutRelease.serviceAccountName (include "imas-farmer.versity.fullname" .) -}}
{{- if eq $sa (toString $other) -}}
{{- fail (printf "versity.createBuckets.serviceAccountName %q is another workload's ServiceAccount: the createBuckets Job gets one of its own, with no RBAC and no token" $sa) -}}
{{- end -}}
{{- end -}}
{{- if not (and (kindIs "string" $v.createBuckets.timeout) (regexMatch "^([0-9]+(\\.[0-9]+)?(ms|s|m|h))+$" (toString $v.createBuckets.timeout))) -}}
{{- fail (printf "versity.createBuckets.timeout must be a Go duration such as \"10m\", got %v" $v.createBuckets.timeout) -}}
{{- end -}}
{{- if not (eq (toString $v.port) (toString (int $v.port))) -}}
{{- fail (printf "versity.port must be a port number, got %v" $v.port) -}}
{{- end -}}
{{- if or (lt (int $v.port) 1024) (gt (int $v.port) 65535) -}}
{{- fail (printf "versity.port must be 1024 to 65535 (the gateway runs as non-root), got %v" $v.port) -}}
{{- end -}}
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
release (version, min_sprout_version, packages, and the GPG-signed
checksums_txt with its base64 checksums_sig; both versions set at release
time) plus this chart's channel, validated here so a bad value fails the
render rather than the hook. saasapi validates every package field again,
and never normalizes; neither does this. Nothing here or in saasapi
verifies checksums_sig: the sprout does (signing design D20).
*/}}
{{- define "imas-farmer.sproutRelease.request" -}}
{{- $r := .Values.sproutRelease -}}
{{- $rel := include "imas-farmer.sproutRelease.file" . | fromJson -}}
{{- if or (hasKey $rel "Error") (not (kindIs "map" $rel)) -}}
{{- fail (printf "files/sprout-release.json is not a JSON object: %v" (get $rel "Error")) -}}
{{- end -}}
{{- range $k, $_ := $rel -}}
{{- if not (has $k (list "version" "min_sprout_version" "packages" "checksums_txt" "checksums_sig")) -}}
{{- fail (printf "files/sprout-release.json has an unexpected field %q: it holds exactly version, min_sprout_version, packages, checksums_txt and checksums_sig (packaging/helm/stamp-sprout-release.sh)" $k) -}}
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
{{- range $k := list "checksums_txt" "checksums_sig" -}}
{{- if or (not (kindIs "string" (get $rel $k))) (not (get $rel $k)) -}}
{{- fail (printf "files/sprout-release.json has no %s; re-stamp it with packaging/helm/stamp-sprout-release.sh" $k) -}}
{{- end -}}
{{- end -}}
{{- if not (regexMatch "^[a-z][a-z0-9_-]{0,31}$" (toString $r.channel)) -}}
{{- fail (printf "sproutRelease.channel %q must match ^[a-z][a-z0-9_-]{0,31}$" (toString $r.channel)) -}}
{{- end -}}
{{- toPrettyJson (dict "version" $version "channel" $r.channel "min_sprout_version" $min "packages" $pkgs "checksums_txt" (get $rel "checksums_txt") "checksums_sig" (get $rel "checksums_sig")) -}}
{{- end }}

{{/*
The OpenBao policies the bootstrap Job writes. The reviewed one
(imas-saasapi-cred-publisher.hcl) is a verbatim copy checked by
chart_test.go against its source; the farmer-only ones are rendered here
from the values they name.
*/}}
{{- define "imas-farmer.policy.farmerGateway" -}}
{{- $g := .Values.farmer.openbao.gateway -}}
# imas-farmer-gateway: farmer's gateway JWT signer (internal/gatewayjwt).
# Exact paths only. A "*" or "+" under transit/sign would also reach
# every other Transit key on the mount.
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
{{- fail "postgresql.* is not a value of this chart: imas's farmer and saas schemas live in one PXC (Percona XtraDB Cluster), not Postgres (docs/design/imas-machine-manager-api-design.md). The bundled database toggle is pxc.enabled; an external one is database.host/existingSecret." -}}
{{- end -}}
{{- if not (regexMatch "^[0-9A-Za-z_-]{1,191}$" (toString .Values.organization)) -}}
{{- fail (printf "organization %q is not a valid tenant ID (^[0-9A-Za-z_-]{1,191}$, internal/pki IsValidTenantID); it is farmerorganization and must equal the nats chart's bus.organization" .Values.organization) -}}
{{- end -}}
{{- if .Values.farmer.adminPubKeys -}}
{{- fail "farmer.adminPubKeys was removed in J.3: every imas CLI request is sealed with the user's CLI box key, so an admin listed by NKey alone can't make a single request. Set farmer.bootstrapAdmin.pubkey and farmer.bootstrapAdmin.boxpub (from the admin's imas auth keygen) instead." -}}
{{- end -}}
{{- with .Values.farmer.bootstrapAdmin -}}
{{- if not (kindIs "bool" (default false .skip)) -}}
{{- fail (printf "farmer.bootstrapAdmin.skip must be true or false, got %v" .skip) -}}
{{- end -}}
{{- if and .skip (or .pubkey .boxpub .username) -}}
{{- fail "farmer.bootstrapAdmin.skip=true and farmer.bootstrapAdmin.pubkey/boxpub/username are both set: choose one. Set the admin's keys for a first install; skip only when an admin already exists in farmer's database." -}}
{{- end -}}
{{- if and (not .skip) (not (or .pubkey .boxpub .username)) -}}
{{- fail "farmer.bootstrapAdmin.pubkey and farmer.bootstrapAdmin.boxpub are required: since J.3 the imas CLI can't add a user over the bus, so an install without a bootstrap admin has no one who can make a single request. Run imas auth keygen on the admin's machine and set both values it prints (see README.md, \"Bootstrap admin\"). If farmer's database already has an admin (an upgrade, or a reinstall against the same database), set farmer.bootstrapAdmin.skip=true instead." -}}
{{- end -}}
{{- if or .pubkey .boxpub .username -}}
{{- if not (regexMatch "^A[A-Z2-7]{55}$" (toString .pubkey)) -}}
{{- fail (printf "farmer.bootstrapAdmin.pubkey %q is not an NKey user public key (imas auth pubkey prints it: A and 55 more base32 characters)" (toString .pubkey)) -}}
{{- end -}}
{{- if not (regexMatch "^[A-Za-z0-9+/]{43}=$" (toString .boxpub)) -}}
{{- fail "farmer.bootstrapAdmin.boxpub is required with pubkey: the CLI box public key (standard base64, 32 bytes) the admin's imas auth keygen printed. Without it the first admin can't make a request." -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- with .Values.bus.host -}}
{{- if or (regexMatch "^[0-9.]+(:[0-9]+)?$" (toString .)) (regexMatch "^\\[?[0-9A-Fa-f]*:[0-9A-Fa-f]*:[0-9A-Fa-f:.%]*\\]?(:[0-9]+)?$" (toString .)) -}}
{{- fail (printf "bus.host %q is an IP address; it must be a DNS name, which the bus certificate carries as a DNS SAN. List the bus's addresses in bus.egressCIDRs instead." (toString .)) -}}
{{- end -}}
{{- if not (regexMatch "^[A-Za-z0-9]([-A-Za-z0-9.]*[A-Za-z0-9])?$" (toString .)) -}}
{{- fail (printf "bus.host %q must be a bare DNS name (farmerbusurl and SAASAPI_NATS_URL are tls://<bus.host>:<bus.port>; the port is bus.port), not a URL or host:port" (toString .)) -}}
{{- end -}}
{{- else -}}
{{- if not .Values.bus.serviceName -}}
{{- fail "bus.serviceName is required: the nats chart's bus client Service (<release>-nats-bus), with bus.namespace its namespace (or bus.host, for a bus outside this cluster)" -}}
{{- end -}}
{{- if not .Values.bus.namespace -}}
{{- fail "bus.namespace is required (or bus.host, for a bus outside this cluster)" -}}
{{- end -}}
{{- end -}}
{{- with .Values.bus.egressCIDRs -}}
{{- if not (kindIs "slice" .) -}}
{{- fail "bus.egressCIDRs must be a list of CIDRs" -}}
{{- end -}}
{{- range . -}}
{{- if not (regexMatch "^([0-9]{1,3}[.]){3}[0-9]{1,3}/[0-9]{1,2}$|^[0-9A-Fa-f:]*:[0-9A-Fa-f:.]*/[0-9]{1,3}$" (toString .)) -}}
{{- fail (printf "bus.egressCIDRs entry %q must be a CIDR (an ipBlock peer, e.g. 10.20.1.4/32)" (toString .)) -}}
{{- end -}}
{{- end -}}
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
{{- range $name := list "SYS_USER" "SAASAPI_USER" -}}
{{- if not (get $seeds $name) -}}
{{- fail (printf "natsSeeds.seeds.%s is required: farmer refuses to start without the %s user seed, and never generates one (see README.md, \"Seeds\")." $name $name) -}}
{{- end -}}
{{- end -}}
{{- range $name := list "OPERATOR" "OPERATOR_SIGNING" "SYS_ACCOUNT" "TENANT" "TENANT_SIGNING" -}}
{{- if hasKey $seeds $name -}}
{{- fail (printf "natsSeeds seed %s was removed in P21 slice 1: the operator, operator-signing, SYS account and tenant keys are OpenBao Transit keys (farmer.openbao.natsSign) and nothing reads a %s seed. Drop it from natsSeeds and from the seed Secret (README.md, \"Seeds\")." $name $name) -}}
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
{{- $nk := .Values.farmer.nkeySecret -}}
{{- if not $nk.secretName -}}
{{- fail "farmer.nkeySecret.secretName is required: farmer's NKey seed, shared by every replica (IMAS_FARMER_NKEY_SEED_FILE). Neither farmer nor this chart generates it (see README.md, \"Seeds\")." -}}
{{- end -}}
{{- if or (gt (len (toString $nk.secretName)) 253) (not (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$" (toString $nk.secretName))) -}}
{{- fail (printf "farmer.nkeySecret.secretName %q is not a valid Secret name" (toString $nk.secretName)) -}}
{{- end -}}
{{- if or (not (regexMatch "^[-._a-zA-Z0-9]+$" (toString $nk.key))) (has (toString $nk.key) (list "." "..")) (hasPrefix ".." (toString $nk.key)) -}}
{{- fail (printf "farmer.nkeySecret.key %q is not a valid Secret key" (toString $nk.key)) -}}
{{- end -}}
{{- if not (hasPrefix "/" (toString $nk.mountPath)) -}}
{{- fail (printf "farmer.nkeySecret.mountPath %q must be an absolute path" (toString $nk.mountPath)) -}}
{{- end -}}
{{- $nkPath := trimSuffix "/" (toString $nk.mountPath) -}}
{{- if or (eq $nkPath "") (eq $nkPath "/tmp") (hasPrefix "/tmp/" $nkPath) -}}
{{- fail (printf "farmer.nkeySecret.mountPath %q must not be /, /tmp or under /tmp: it would hide farmer's writable tmp volume (the process's temp directory)" (toString $nk.mountPath)) -}}
{{- end -}}
{{- if eq $nkPath (trimSuffix "/" (toString .Values.natsSeeds.mountPath)) -}}
{{- fail "farmer.nkeySecret.mountPath must differ from natsSeeds.mountPath" -}}
{{- end -}}
{{- if has $nk.secretName (list .Values.natsSeeds.secretName .Values.saasapi.natsCredentials.secretName) -}}
{{- fail (printf "farmer.nkeySecret.secretName %q must be a Secret of its own: farmer's NKey is mounted only in farmer's pods, and ESO writes it from its own ExternalSecret" $nk.secretName) -}}
{{- end -}}
{{- if not (has .Values.tls.mode (list "secret" "openbao")) -}}
{{- fail (printf "tls.mode must be \"secret\" or \"openbao\", got %q" .Values.tls.mode) -}}
{{- end -}}
{{- if and (eq .Values.tls.mode "secret") (not .Values.tls.secretName) -}}
{{- fail "tls.secretName is required when tls.mode=secret" -}}
{{- end -}}
{{- include "imas-farmer.saasapiBox.validate" . -}}
{{- if not (include "imas-farmer.openbaoAddr" .) -}}
{{- fail "openbaoClient.addr is required when openbao.enabled=false (farmer's gateway signer, tenant box and the publish Job all need OpenBao)" -}}
{{- end -}}
{{- if not (has .Values.openbaoClient.authMethod (list "kubernetes" "token")) -}}
{{- fail "openbaoClient.authMethod must be \"kubernetes\" or \"token\"" -}}
{{- end -}}
{{- if and (eq .Values.openbaoClient.authMethod "token") (not .Values.openbaoClient.tokenSecretName) -}}
{{- fail "openbaoClient.tokenSecretName is required when authMethod=token" -}}
{{- end -}}
{{- include "imas-farmer.natsSign.validate" . -}}
{{- if not (include "imas-farmer.dbHost" .) -}}
{{- fail "database.host is required when pxc.enabled=false" -}}
{{- end -}}
{{- if hasKey .Values.database "bootstrap" -}}
{{- fail "database.bootstrap.* was replaced by database.migrate.* (the cmd/migrate hook Job, docs/design/imas-machine-manager-api-design.md §4.1a): rootPasswordSecret, rootPasswordKey, activeDeadlineSeconds and resources moved there. There is no enabled toggle: farmer and saasapi no longer migrate their own schemas." -}}
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
{{- $fr := .Values.farmer.replicaCount -}}
{{- if or (not (or (kindIs "float64" $fr) (kindIs "int64" $fr) (kindIs "int" $fr))) (ne (float64 $fr) (float64 (int $fr))) (lt (int $fr) 1) -}}
{{- fail (printf "farmer.replicaCount must be a whole number of at least 1, got %v" $fr) -}}
{{- end -}}
{{- with .Values.farmer.jobs.reconcileWindow -}}
{{- if not (kindIs "string" .) -}}
{{- fail (printf "farmer.jobs.reconcileWindow must be a quoted duration such as \"2h\", got %v" .) -}}
{{- end -}}
{{- end -}}
{{- $durations := dict "farmer.jobs.leaseTTL" .Values.farmer.jobs.leaseTTL -}}
{{- with .Values.farmer.tenantConnections -}}
{{- $_ := set $durations "farmer.tenantConnections.idleTTL" .idleTTL -}}
{{- $_ := set $durations "farmer.tenantConnections.heartbeatWindow" .heartbeatWindow -}}
{{- end -}}
{{- range $k, $v := $durations -}}
{{- if and $v (not (kindIs "string" $v)) -}}
{{- fail (printf "%s must be a quoted duration such as \"10m\", got %v" $k $v) -}}
{{- end -}}
{{- end -}}
{{- range $k, $v := dict "farmer.logFormat" .Values.farmer.logFormat "saasapi.logFormat" .Values.saasapi.logFormat -}}
{{- if and $v (not (has (toString $v) (list "json" "text"))) -}}
{{- fail (printf "%s must be \"json\" or \"text\" (IMAS_LOG_FORMAT), got %v" $k $v) -}}
{{- end -}}
{{- end -}}
{{- with .Values.objectStore.sproutJWTBucket -}}
{{- if or (eq . (toString $.Values.objectStore.bucket)) (eq . (toString $.Values.objectStore.jobBucket)) -}}
{{- fail (printf "objectStore.sproutJWTBucket %q must differ from objectStore.bucket and objectStore.jobBucket: sprout User JWTs are private, and GET /files/ serves every key in the recipe bucket" .) -}}
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
{{- include "imas-farmer.accountStore.validate" . -}}
{{- if .Values.versity.enabled -}}
{{- include "imas-farmer.versity.validate" . -}}
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

{{/* The accounts bucket (accountStore) is required and its own: a bucket,
an endpoint (its own or objectStore.endpoint) and a write credential of
its own, which farmer checks again at start. Without it a bus node that
restarts loads no Account, so farmer refuses to start and this chart
refuses to render. */}}
{{- define "imas-farmer.accountStore.validate" -}}
{{- $n := .Values.bus.expectedNodes -}}
{{- if not (or (kindIs "invalid" $n) (and (kindIs "float64" $n) (ge (float64 $n) 0.0) (eq (float64 $n) (float64 (int64 $n)))) (and (kindIs "int64" $n) (ge (int64 $n) 0)) (and (kindIs "int" $n) (ge (int $n) 0))) -}}
{{- fail (printf "bus.expectedNodes must be a whole number, 0 or more, got %v" $n) -}}
{{- end -}}
{{- $acc := .Values.accountStore -}}
{{- $os := .Values.objectStore -}}
{{- if not $acc.bucket -}}
{{- fail "accountStore.bucket is required: farmer writes every Account JWT there, and a bus node that restarts loads its Accounts from it (the bus keeps none of its own)" -}}
{{- end -}}
{{- if not (or $acc.endpoint (include "imas-farmer.s3Endpoint" .)) -}}
{{- fail "accountStore.endpoint (or objectStore.endpoint, or versity.enabled) is required: farmer writes every Account JWT to the accounts bucket, and a bus node that restarts loads its Accounts from it (the bus keeps none of its own)" -}}
{{- end -}}
{{- if not $acc.credentialsSecret -}}
{{- fail "accountStore.credentialsSecret is required: farmer writes the accounts bucket with a credential of its own" -}}
{{- end -}}
{{- if eq (toString $acc.credentialsSecret) (toString $os.credentialsSecret) -}}
{{- fail "accountStore.credentialsSecret must not be objectStore.credentialsSecret: the accounts bucket needs a write credential of its own, which can't reach the recipe, job or sprout JWT bucket" -}}
{{- end -}}
{{- range $b := list $os.bucket $os.jobBucket $os.sproutJWTBucket -}}
{{- if and $b (eq (toString $b) (toString $acc.bucket)) -}}
{{- fail (printf "accountStore.bucket %q must differ from objectStore.bucket, objectStore.jobBucket and objectStore.sproutJWTBucket: the accounts bucket is its own" $acc.bucket) -}}
{{- end -}}
{{- end -}}
{{- if not (or (kindIs "invalid" $acc.useSSL) (kindIs "bool" $acc.useSSL)) -}}
{{- fail (printf "accountStore.useSSL must be true, false or null, got %v" $acc.useSSL) -}}
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
{{- if not (kindIs "bool" $r.credentialCheck) -}}
{{- fail (printf "saasapi.recipes.credentialCheck must be true or false, got %v" $r.credentialCheck) -}}
{{- end -}}
{{- if $r.enabled -}}
{{- if not $r.credentialsSecret -}}
{{- fail "saasapi.recipes.credentialsSecret is required with saasapi.recipes.enabled: saasapi's OWN object-store access key pair, limited to tenants/*/recipes/* (files/objectstore-policies/)" -}}
{{- end -}}
{{- if eq (toString $r.credentialsSecret) (toString .Values.objectStore.credentialsSecret) -}}
{{- fail "saasapi.recipes.credentialsSecret must not be objectStore.credentialsSecret: farmer's credential can write sprouts/ and the platform recipe prefix, saasapi's must only reach tenants/*/recipes/*" -}}
{{- end -}}
{{- if or (not (include "imas-farmer.s3Endpoint" .)) (not .Values.objectStore.bucket) -}}
{{- fail "saasapi.recipes.enabled needs objectStore.endpoint (or versity.enabled) and objectStore.bucket: saasapi writes the bucket farmer cooks from" -}}
{{- end -}}
{{- if and $r.credentialCheck (not .Values.objectStore.jobBucket) -}}
{{- fail "objectStore.jobBucket is required with saasapi.recipes.enabled and saasapi.recipes.credentialCheck: saasapi's startup check makes sure its recipe credential can't reach farmer's job bucket (SAASAPI_RECIPES_JOB_BUCKET), and refuses to start without knowing which bucket that is" -}}
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
{{- range $other := list $s.internalAuthSecret.secretName $s.natsCredentials.secretName $o.tls.secretName .Values.natsSeeds.secretName .Values.farmer.nkeySecret.secretName -}}
{{- if eq (toString $o.token.secretName) (toString $other) -}}
{{- fail (printf "saasapi.operator.token.secretName %q must be a Secret of its own: the registration Job mounts it, and must never be able to mount another credential with it (saasapi also refuses an operator token equal to the BFF's)" $o.token.secretName) -}}
{{- end -}}
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
{{- range $r := list .Values.tls.openbao.k8sRole .Values.farmer.openbao.gateway.k8sRole .Values.farmer.openbao.tenantBox.k8sRole .Values.farmer.openbao.natsSign.k8sRole -}}
{{- if or (eq $r $p.k8sRole) (eq $r $p.natsSign.k8sRole) -}}
{{- fail (printf "credentialPublisher.k8sRole %q or credentialPublisher.natsSign.k8sRole %q is also one of farmer's OpenBao roles: the publisher's roles must never be ones farmer can log in with" $p.k8sRole $p.natsSign.k8sRole) -}}
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
{{- $others := list .Values.natsSeeds.secretName .Values.farmer.nkeySecret.secretName .Values.saasapi.natsCredentials.secretName (include "imas-farmer.dbSecretName" .) .Values.saasapi.internalAuthSecret.secretName -}}
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
{{- range $r := list .Values.tls.openbao.k8sRole .Values.farmer.openbao.gateway.k8sRole .Values.farmer.openbao.tenantBox.k8sRole .Values.farmer.openbao.natsSign.k8sRole .Values.credentialPublisher.k8sRole .Values.credentialPublisher.natsSign.k8sRole -}}
{{- if eq $r $c.k8sRole -}}
{{- fail (printf "controlPlaneBoxKeys.k8sRole %q is another workload's OpenBao role" $c.k8sRole) -}}
{{- end -}}
{{- end -}}
{{- end }}

{{/*
The NATS trust chain signer (P21 slice 1). Its policies
(files/openbao-policies/imas-farmer-natssign.hcl, imas-nats-sys-signer.hcl,
imas-nats-bootstrap.hcl) name the "transit" mount and the fixed key names,
so a value that would point a client elsewhere is refused rather than
silently uncovered. Each signer role is its own.
*/}}
{{- define "imas-farmer.natsSign.validate" -}}
{{- $n := .Values.farmer.openbao.natsSign -}}
{{- if ne (toString $n.transitMount) "transit" -}}
{{- fail (printf "farmer.openbao.natsSign.transitMount %q: the reviewed policies in files/openbao-policies (imas-farmer-natssign, imas-nats-sys-signer, imas-nats-bootstrap) grant the transit/ mount only. Keep it \"transit\", or change the policies (and their review) with it." (toString $n.transitMount)) -}}
{{- end -}}
{{- if not (regexMatch "^[1-9][0-9]*(ms|s|m)$" (toString $n.timeout)) -}}
{{- fail (printf "farmer.openbao.natsSign.timeout %q must be a positive whole number of ms, s or m, such as \"15s\" (IMAS_NATSSIGN_TIMEOUT)" (toString $n.timeout)) -}}
{{- end -}}
{{- range $k := list "batchMax" "workers" "retiredTenantKeyRetentionDays" -}}
{{- $v := get $n $k -}}
{{- if not (or (kindIs "float64" $v) (kindIs "int64" $v) (kindIs "int" $v)) -}}
{{- fail (printf "farmer.openbao.natsSign.%s must be a positive whole number, got %v" $k $v) -}}
{{- end -}}
{{- if or (lt (float64 $v) 1.0) (ne (float64 $v) (float64 (int64 $v))) -}}
{{- fail (printf "farmer.openbao.natsSign.%s must be a positive whole number, got %v" $k $v) -}}
{{- end -}}
{{- end -}}
{{- if has $n.k8sRole (list .Values.tls.openbao.k8sRole .Values.farmer.openbao.gateway.k8sRole .Values.farmer.openbao.tenantBox.k8sRole) -}}
{{- fail (printf "farmer.openbao.natsSign.k8sRole %q is another of farmer's OpenBao roles: one role per client, one policy per role" $n.k8sRole) -}}
{{- end -}}
{{- $t := .Values.natsTrust -}}
{{- if not (regexMatch "^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$" (toString $t.configMapName)) -}}
{{- fail (printf "natsTrust.configMapName %q is not a valid ConfigMap name" (toString $t.configMapName)) -}}
{{- end -}}
{{- with $t.busFenceUserPub -}}
{{- if not (regexMatch "^U[A-Z2-7]{55}$" (toString .)) -}}
{{- fail (printf "natsTrust.busFenceUserPub %q is not an NKey user public key (U and 55 more base32 characters): the public half of the nats chart's BUS_FENCE_USER seed" (toString .)) -}}
{{- end -}}
{{- end -}}
{{- with $t.busLoaderUserPub -}}
{{- if not (regexMatch "^U[A-Z2-7]{55}$" (toString .)) -}}
{{- fail (printf "natsTrust.busLoaderUserPub %q is not an NKey user public key (U and 55 more base32 characters): the public half of the nats chart's loader.sysUserSecret seed" (toString .)) -}}
{{- end -}}
{{- if eq (toString .) (toString $t.busFenceUserPub) -}}
{{- fail "natsTrust.busLoaderUserPub and natsTrust.busFenceUserPub must be different keys: the loader and the fence are separate SYS users with separate grants" -}}
{{- end -}}
{{- end -}}
{{- end }}

{{/* The trust ConfigMap volume and mount (IMAS_NATS_TRUST_DIR). */}}
{{- define "imas-farmer.natsTrustDir" -}}
/var/run/imas/nats-trust
{{- end }}

{{- define "imas-farmer.natsTrustVolume" -}}
- name: nats-trust
  configMap:
    name: {{ .Values.natsTrust.configMapName }}
{{- end }}

{{- define "imas-farmer.natsTrustVolumeMount" -}}
- name: nats-trust
  mountPath: {{ include "imas-farmer.natsTrustDir" . }}
  readOnly: true
{{- end }}

{{/*
IMAS_NATSSIGN_* for one signer identity (internal/pki/natskeys env.go).
Call with (dict "root" $ "k8sRole" <role> "tokenKey" <key>) plus an
optional "tokenSecret".
*/}}
{{- define "imas-farmer.natsSignEnv" -}}
{{- $n := .root.Values.farmer.openbao.natsSign -}}
{{- include "imas-farmer.openbaoEnv" (dict "root" .root "prefix" "IMAS_NATSSIGN_OPENBAO" "k8sRole" .k8sRole "tokenKey" .tokenKey "tokenSecret" .tokenSecret) }}
- name: IMAS_NATSSIGN_OPENBAO_TRANSIT_MOUNT
  value: {{ $n.transitMount | quote }}
- name: IMAS_NATSSIGN_TIMEOUT
  value: {{ $n.timeout | quote }}
- name: IMAS_NATSSIGN_BATCH_MAX
  value: {{ $n.batchMax | int64 | toString | quote }}
- name: IMAS_NATSSIGN_WORKERS
  value: {{ $n.workers | int64 | toString | quote }}
- name: IMAS_NATS_TRUST_DIR
  value: {{ include "imas-farmer.natsTrustDir" .root | quote }}
{{- end }}

{{/*
The bootstrap Job's egress rule to the Kubernetes API (its nats-trust
container reads and writes the trust ConfigMap): networkPolicy.external.
kubeApi.cidrs as ipBlock peers (empty: any destination), on its ports.
*/}}
{{- define "imas-farmer.kubeApiEgress" -}}
{{- $k := .Values.networkPolicy.external.kubeApi -}}
- ports:
    {{- range $k.ports }}
    - { protocol: TCP, port: {{ int . }} }
    {{- end }}
  {{- with $k.cidrs }}
  to:
    {{- range . }}
    - ipBlock:
        cidr: {{ . | quote }}
    {{- end }}
  {{- end }}
{{- end }}

{{/*
The bao containers of the bootstrap Job: address, CA, and the bootstrap
token from openbaoBootstrap.tokenSecretName (or the dev Secret). The
reference is optional: no Secret, no token, and the Job only checks.
*/}}
{{- define "imas-farmer.bootstrapBaoEnv" -}}
{{- $bs := .Values.openbaoBootstrap -}}
- name: BAO_ADDR
  value: {{ include "imas-farmer.openbaoAddr" . | quote }}
- name: BAO_TOKEN
  valueFrom:
    secretKeyRef:
      name: {{ default (printf "%s-openbao-bootstrap" (include "imas-farmer.fullname" .)) $bs.tokenSecretName }}
      key: {{ $bs.tokenSecretKey }}
      optional: true
{{- if .Values.openbaoClient.caConfigMap }}
- name: BAO_CACERT
  value: /var/run/secrets/openbao-ca/{{ .Values.openbaoClient.caKey }}
{{- end }}
- name: HOME
  value: /tmp
{{- end }}

{{/* True (non-empty) when the bootstrap Job revokes its own token:
openbaoBootstrap.revokeToken, never in dev mode. */}}
{{- define "imas-farmer.bootstrap.revokesToken" -}}
{{- $dev := and .Values.openbao.server .Values.openbao.server.dev .Values.openbao.server.dev.enabled -}}
{{- if and .Values.openbaoBootstrap.revokeToken (not $dev) -}}true{{- end -}}
{{- end }}

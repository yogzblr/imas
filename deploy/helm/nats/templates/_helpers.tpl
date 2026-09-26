{{/*
Naming.
*/}}
{{- define "imas-nats.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "imas-nats.fullname" -}}
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

{{/* Leaves room for the "-headless" suffix and StatefulSet ordinals. */}}
{{- define "imas-nats.bus.fullname" -}}
{{- printf "%s-bus" (include "imas-nats.fullname" .) | trunc 45 | trimSuffix "-" }}
{{- end }}

{{- define "imas-nats.bus.headless" -}}
{{- printf "%s-headless" (include "imas-nats.bus.fullname" .) }}
{{- end }}

{{- define "imas-nats.envoy.fullname" -}}
{{- printf "%s-envoy" (include "imas-nats.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "imas-nats.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Labels. "component" separates the bus from Envoy so selectors (and the
NetworkPolicies) never match the other workload.
*/}}
{{- define "imas-nats.labels" -}}
helm.sh/chart: {{ include "imas-nats.chart" . }}
app.kubernetes.io/name: {{ include "imas-nats.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: imas
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{- define "imas-nats.bus.selectorLabels" -}}
app.kubernetes.io/name: {{ include "imas-nats.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: bus
{{- end }}

{{- define "imas-nats.envoy.selectorLabels" -}}
app.kubernetes.io/name: {{ include "imas-nats.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: envoy
{{- end }}

{{- define "imas-nats.bus.serviceAccountName" -}}
{{- if .Values.bus.serviceAccount.create }}
{{- default (include "imas-nats.bus.fullname" .) .Values.bus.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.bus.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "imas-nats.envoy.serviceAccountName" -}}
{{- if .Values.envoy.serviceAccount.create }}
{{- default (include "imas-nats.envoy.fullname" .) .Values.envoy.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.envoy.serviceAccount.name }}
{{- end }}
{{- end }}

{{/* image reference: repository[:tag][@digest] */}}
{{- define "imas-nats.image" -}}
{{- $img := .image -}}
{{- if $img.digest -}}
{{- printf "%s@%s" $img.repository $img.digest -}}
{{- else -}}
{{- printf "%s:%s" $img.repository (toString (default .appVersion $img.tag)) -}}
{{- end -}}
{{- end }}

{{- define "imas-nats.clusterDomain" -}}
cluster.local
{{- end }}

{{/* In-cluster DNS name of the bus client Service. */}}
{{- define "imas-nats.bus.serviceFQDN" -}}
{{- printf "%s.%s.svc.%s" (include "imas-nats.bus.fullname" .) .Release.Namespace (include "imas-nats.clusterDomain" .) }}
{{- end }}

{{/*
Seeds: natsSeeds.seeds merged with natsSeeds.extraSeeds, as a dict of
NAME -> secret key. Output is YAML so callers can fromYaml it.
*/}}
{{- define "imas-nats.seeds" -}}
{{- $all := merge (dict) (deepCopy (default (dict) .Values.natsSeeds.extraSeeds)) (deepCopy (default (dict) .Values.natsSeeds.seeds)) -}}
{{- toYaml $all -}}
{{- end }}

{{/*
Bus TLS file paths inside the container, per bus.tls.mode.
*/}}
{{- define "imas-nats.bus.tlsDir" -}}
{{- if eq .Values.bus.tls.mode "secret" -}}
/etc/imas/tls
{{- else -}}
/var/run/imas/tls
{{- end -}}
{{- end }}

{{/*
The SANs the bus cert must carry: the client Service (short, namespaced
and FQDN forms) plus every pod's headless name.
*/}}
{{- define "imas-nats.bus.defaultCertHosts" -}}
{{- $svc := include "imas-nats.bus.fullname" . -}}
{{- $hl := include "imas-nats.bus.headless" . -}}
{{- $ns := .Release.Namespace -}}
{{- $cd := include "imas-nats.clusterDomain" . -}}
{{- $hosts := list $svc (printf "%s.%s" $svc $ns) (printf "%s.%s.svc" $svc $ns) (printf "%s.%s.svc.%s" $svc $ns $cd) -}}
{{- range $i := until (int .Values.bus.replicaCount) -}}
{{- $hosts = append $hosts (printf "%s-%d.%s.%s.svc.%s" $svc $i $hl $ns $cd) -}}
{{- end -}}
{{- toYaml $hosts -}}
{{- end }}

{{/* Comma-separated nats-route URLs to every bus pod. */}}
{{- define "imas-nats.bus.routes" -}}
{{- $svc := include "imas-nats.bus.fullname" . -}}
{{- $hl := include "imas-nats.bus.headless" . -}}
{{- $routes := list -}}
{{- range $i := until (int .Values.bus.replicaCount) -}}
{{- $routes = append $routes (printf "tls://%s-%d.%s.%s.svc.%s:%d" $svc $i $hl $.Release.Namespace (include "imas-nats.clusterDomain" $) (int $.Values.bus.cluster.port)) -}}
{{- end -}}
{{- join "," $routes -}}
{{- end }}

{{/*
Render-time validation. Everything here fails the render with an
explanation rather than deploying something that silently can't work.
*/}}
{{- define "imas-nats.validate" -}}
{{- if not .Values.natsSeeds.secretName -}}
{{- fail "natsSeeds.secretName is required: this chart never generates NATS seeds. Point it at the Secret ESO syncs from OpenBao (see deploy/farmer/externalsecrets.yaml)." -}}
{{- end -}}
{{- $seeds := fromYaml (include "imas-nats.seeds" .) -}}
{{- range $name := list "OPERATOR" "OPERATOR_SIGNING" "SYS_ACCOUNT" "TENANT" "TENANT_SIGNING" -}}
{{- if not (get $seeds $name) -}}
{{- fail (printf "natsSeeds.seeds.%s is required. Without it farmerbus generates its own %s seed on its PVC, which diverges from cmd/farmer's trust chain (see README.md, \"Seeds\")." $name $name) -}}
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
{{- if not (regexMatch "^[0-9A-Za-z_-]{1,191}$" (toString .Values.bus.organization)) -}}
{{- fail (printf "bus.organization %q is not a valid tenant ID (^[0-9A-Za-z_-]{1,191}$, internal/pki IsValidTenantID); it names the legacy tenant and must match cmd/farmer's farmerorganization" .Values.bus.organization) -}}
{{- end -}}
{{- if lt (int .Values.bus.replicaCount) 1 -}}
{{- fail "bus.replicaCount must be at least 1" -}}
{{- end -}}
{{- if and (gt (int .Values.bus.replicaCount) 1) (not .Values.bus.cluster.routesSupported) -}}
{{- fail "bus.replicaCount > 1 needs NATS cluster routes, which cmd/farmerbus does not configure yet (internal/pki/nats.go's ConfigureNats sets no Cluster options). Extra replicas would be un-meshed servers: a claims push or a publish reaching one node would never reach the others. Set bus.cluster.routesSupported=true only once farmerbus reads IMAS_BUS_CLUSTER_* (see README.md, \"Clustering\")." -}}
{{- end -}}
{{- if not (has .Values.bus.tls.mode (list "secret" "openbao")) -}}
{{- fail (printf "bus.tls.mode must be \"secret\" or \"openbao\", got %q" .Values.bus.tls.mode) -}}
{{- end -}}
{{- if and (eq .Values.bus.tls.mode "secret") (not .Values.bus.tls.secretName) -}}
{{- fail "bus.tls.secretName is required when bus.tls.mode=secret" -}}
{{- end -}}
{{- if eq .Values.bus.tls.mode "openbao" -}}
{{- if or (not .Values.bus.tls.openbao.addr) (not .Values.bus.tls.openbao.role) -}}
{{- fail "bus.tls.openbao.addr and bus.tls.openbao.role are required when bus.tls.mode=openbao" -}}
{{- end -}}
{{- if not (has .Values.bus.tls.openbao.authMethod (list "kubernetes" "token")) -}}
{{- fail "bus.tls.openbao.authMethod must be \"kubernetes\" or \"token\"" -}}
{{- end -}}
{{- if and (eq .Values.bus.tls.openbao.authMethod "token") (not .Values.bus.tls.openbao.tokenSecretName) -}}
{{- fail "bus.tls.openbao.tokenSecretName is required when authMethod=token" -}}
{{- end -}}
{{- if and (eq .Values.bus.tls.openbao.authMethod "kubernetes") (not .Values.bus.tls.openbao.k8sRole) -}}
{{- fail "bus.tls.openbao.k8sRole is required when authMethod=kubernetes" -}}
{{- end -}}
{{- end -}}
{{- if .Values.envoy.enabled -}}
{{- include "imas-nats.envoy.validate" . -}}
{{- end -}}
{{- end }}

{{- define "imas-nats.envoy.validate" -}}
{{- $e := .Values.envoy -}}
{{- if not $e.tls.secretName -}}
{{- fail "envoy.tls.secretName is required: the DMZ listener only serves TLS" -}}
{{- end -}}
{{- if not $e.jwtAuthn.issuer -}}
{{- fail "envoy.jwtAuthn.issuer is required (internal/gatewayjwt's GatewayIssuer, \"imas-gateway\")" -}}
{{- end -}}
{{- if not $e.upstreams.farmerAPI.host -}}
{{- fail "envoy.upstreams.farmerAPI.host is required (/v1/enroll and /v1/recipes proxy to it)" -}}
{{- end -}}
{{- $src := $e.jwtAuthn.jwks.source -}}
{{- if not (has $src (list "remote" "local")) -}}
{{- fail (printf "envoy.jwtAuthn.jwks.source must be \"remote\" or \"local\", got %q" $src) -}}
{{- end -}}
{{- if eq $src "remote" -}}
{{- if not (has $e.jwtAuthn.jwks.remote.cluster (list "farmer_api" "jwks")) -}}
{{- fail "envoy.jwtAuthn.jwks.remote.cluster must be \"farmer_api\" or \"jwks\"" -}}
{{- end -}}
{{- if and (eq $e.jwtAuthn.jwks.remote.cluster "jwks") (not $e.upstreams.jwks.host) -}}
{{- fail "envoy.upstreams.jwks.host is required when jwks.remote.cluster=jwks" -}}
{{- end -}}
{{- end -}}
{{- if eq $src "local" -}}
{{- if and (not $e.jwtAuthn.jwks.local.inline) (not $e.jwtAuthn.jwks.local.configMapName) -}}
{{- fail "envoy.jwtAuthn.jwks.source=local needs jwks.local.inline or jwks.local.configMapName" -}}
{{- end -}}
{{- if and $e.jwtAuthn.jwks.local.inline $e.jwtAuthn.jwks.local.configMapName -}}
{{- fail "set only one of envoy.jwtAuthn.jwks.local.inline and configMapName" -}}
{{- end -}}
{{- if $e.jwtAuthn.jwks.local.inline -}}
{{- $doc := fromJson $e.jwtAuthn.jwks.local.inline -}}
{{- if or (hasKey $doc "Error") (not (hasKey $doc "keys")) -}}
{{- fail "envoy.jwtAuthn.jwks.local.inline must be a JSON JWKS document with a \"keys\" array" -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if and $e.upstreamTLS.caSecretName $e.upstreamTLS.caConfigMapName -}}
{{- fail "set only one of envoy.upstreamTLS.caSecretName and caConfigMapName" -}}
{{- end -}}
{{- end }}

{{/* True (non-empty) when Envoy verifies upstream certs. */}}
{{- define "imas-nats.envoy.verifyUpstream" -}}
{{- if or .Values.envoy.upstreamTLS.caSecretName .Values.envoy.upstreamTLS.caConfigMapName -}}true{{- end -}}
{{- end }}

{{/*
UpstreamTlsContext for one Envoy cluster. Call with
(dict "root" $ "sni" <sni>).
*/}}
{{- define "imas-nats.envoy.upstreamTLS" -}}
transport_socket:
  name: envoy.transport_sockets.tls
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
    sni: {{ .sni | quote }}
    {{- if include "imas-nats.envoy.verifyUpstream" .root }}
    common_tls_context:
      validation_context:
        trusted_ca: { filename: "/etc/envoy/upstream-ca/{{ .root.Values.envoy.upstreamTLS.caKey }}" }
        match_typed_subject_alt_names:
          - san_type: DNS
            matcher: { exact: {{ .sni | quote }} }
    {{- end }}
{{- end }}

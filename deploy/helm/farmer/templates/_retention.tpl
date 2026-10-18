{{/*
Retention values (docs/retention.md, U4): types and shapes here, ranges
by the binaries at startup, which refuse a value outside them naming the
variable. Included from imas-farmer.validate.
*/}}
{{- define "imas-farmer.retention.validate" -}}
{{- $goDuration := `^([0-9]+(\.[0-9]+)?(h|m|s|ms|us|ns))+$|^0$` -}}
{{- $r := .Values.farmer.retention -}}
{{- range $k, $v := dict "farmer.retention.jobLogTTL" $r.jobLogTTL "farmer.retention.boxKeyGrace" $r.boxKeyGrace "saasapi.retention.terminalRows" .Values.saasapi.retention.terminalRows -}}
{{- if not (or (kindIs "invalid" $v) (and (kindIs "string" $v) (or (eq $v "") (regexMatch $goDuration $v)))) -}}
{{- fail (printf "%s must be a quoted Go duration such as \"720h\", \"0\" for the default, or null, got %v" $k $v) -}}
{{- end -}}
{{- end -}}
{{- include "imas-farmer.retention.days" (dict "key" "farmer.retention.recipeAuditDays" "value" $r.recipeAuditDays "zero" "keeps them for ever") -}}
{{- $l := .Values.logShipping -}}
{{- if $l.enabled -}}
{{- if not $l.image.digest -}}
{{- fail "logShipping.image.digest is required: the shipper is pinned by digest" -}}
{{- end -}}
{{- if not (regexMatch `^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$` (toString $l.bucket)) -}}
{{- fail (printf "logShipping.bucket %q must be 3 to 63 lower-case letters, digits and hyphens (an S3 bucket and Azure Blob container name)" (toString $l.bucket)) -}}
{{- end -}}
{{- range $k, $b := dict "objectStore.bucket" $.Values.objectStore.bucket "objectStore.jobBucket" $.Values.objectStore.jobBucket "objectStore.sproutJWTBucket" $.Values.objectStore.sproutJWTBucket "accountStore.bucket" $.Values.accountStore.bucket -}}
{{- if eq (toString $b) (toString $l.bucket) -}}
{{- fail (printf "logShipping.bucket %q must differ from %s: the log credentials reach only the log bucket" (toString $l.bucket) $k) -}}
{{- end -}}
{{- end -}}
{{- if not (regexMatch `^[a-z0-9][a-z0-9._-]*(/[a-z0-9][a-z0-9._-]*)*/$` (toString $l.prefix)) -}}
{{- fail (printf "logShipping.prefix %q must be a key root such as logs/: lower-case segments, ending in / and not starting with one" (toString $l.prefix)) -}}
{{- end -}}
{{- if not (regexMatch `^[0-9]+[KMG]?$` (toString $l.totalFileSize)) -}}
{{- fail (printf "logShipping.totalFileSize must be a size such as 50M, got %v" $l.totalFileSize) -}}
{{- end -}}
{{- if not (and (kindIs "string" $l.uploadTimeout) (regexMatch `^[0-9]+[smh]$` $l.uploadTimeout)) -}}
{{- fail (printf "logShipping.uploadTimeout must be a quoted time such as \"10m\" (s, m or h), got %v" $l.uploadTimeout) -}}
{{- end -}}
{{- include "imas-farmer.retention.days" (dict "key" "logShipping.retention.days" "value" $l.retention.days "zero" "is the default, 30") -}}
{{- if not $l.existingConfigMap -}}
{{- if not (include "imas-farmer.s3Endpoint" .) -}}
{{- fail "logShipping.enabled needs an object store: set objectStore.endpoint, or versity.enabled (or logShipping.existingConfigMap to ship elsewhere)" -}}
{{- end -}}
{{- if not $l.credentialsSecret -}}
{{- fail "logShipping.credentialsSecret is required: the writer's access key pair (PutObject under logShipping.prefix only)" -}}
{{- end -}}
{{- if not $l.retention.credentialsSecret -}}
{{- fail "logShipping.retention.credentialsSecret is required: the retention CronJob's access key pair (ListBucket, and DeleteObject under logShipping.prefix only)" -}}
{{- end -}}
{{- $others := dict "logShipping.retention.credentialsSecret" $l.retention.credentialsSecret "objectStore.credentialsSecret" .Values.objectStore.credentialsSecret "accountStore.credentialsSecret" .Values.accountStore.credentialsSecret "saasapi.recipes.credentialsSecret" .Values.saasapi.recipes.credentialsSecret "versity.accountsReader.credentialsSecret" .Values.versity.accountsReader.credentialsSecret "versity.rootCredentials.secretName" .Values.versity.rootCredentials.secretName -}}
{{- range $k, $sec := $others -}}
{{- if eq (toString $sec) (toString $l.credentialsSecret) -}}
{{- fail (printf "logShipping.credentialsSecret must differ from %s: the shipper's credential may only write logs" $k) -}}
{{- end -}}
{{- if and (ne $k "logShipping.retention.credentialsSecret") (eq (toString $sec) (toString $l.retention.credentialsSecret)) -}}
{{- fail (printf "logShipping.retention.credentialsSecret must differ from %s: the retention credential may only list and delete logs" $k) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end }}

{{/* A whole number of days from 0 to 3650, or null or "" (.key names
it in the message; .zero says what 0 means). */}}
{{- define "imas-farmer.retention.days" -}}
{{- $v := .value -}}
{{- if not (or (kindIs "invalid" $v) (eq (toString $v) "")) -}}
{{- if not (or (kindIs "int" $v) (kindIs "int64" $v) (kindIs "float64" $v)) -}}
{{- fail (printf "%s must be a whole number of days from 0 to 3650 (0 %s), got %v" .key .zero $v) -}}
{{- end -}}
{{- if or (ne (float64 $v) (float64 (int64 $v))) (lt (int64 $v) 0) (gt (int64 $v) 3650) -}}
{{- fail (printf "%s must be a whole number of days from 0 to 3650 (0 %s), got %v" .key .zero $v) -}}
{{- end -}}
{{- end -}}
{{- end }}

{{/* The log shipper's names and labels. */}}
{{- define "imas-farmer.logShipping.fullname" -}}
{{- printf "%s-log-shipper" (include "imas-farmer.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "imas-farmer.logShipping.selectorLabels" -}}
app.kubernetes.io/name: imas-log-shipper
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: log-shipper
{{- end }}

{{- define "imas-farmer.logRetention.fullname" -}}
{{- printf "%s-log-retention" (include "imas-farmer.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "imas-farmer.logRetention.selectorLabels" -}}
app.kubernetes.io/name: imas-log-shipper
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: log-retention
{{- end }}

{{- define "imas-farmer.logShipping.image" -}}
{{- include "imas-farmer.image" (dict "image" .Values.logShipping.image "appVersion" "") -}}
{{- end }}

{{/* True (non-empty) when the chart's own Fluent Bit configuration and the
retention CronJob are rendered: shipping on, no existingConfigMap. */}}
{{- define "imas-farmer.logShipping.ownOutput" -}}
{{- if and .Values.logShipping.enabled (not .Values.logShipping.existingConfigMap) -}}true{{- end -}}
{{- end }}

{{/* The retention CronJob's days: logShipping.retention.days, 30 for 0 or
null. */}}
{{- define "imas-farmer.logRetention.days" -}}
{{- $d := .Values.logShipping.retention.days -}}
{{- if or (kindIs "invalid" $d) (eq (toString $d) "") (eq (int64 $d) 0) -}}30{{- else -}}{{ int64 $d }}{{- end -}}
{{- end }}

{{/* The Fluent Bit configuration (YAML) of the chart's own output. */}}
{{- define "imas-farmer.logShipping.config" -}}
{{- $l := .Values.logShipping -}}
{{- $paths := $l.paths | default (list (printf "/var/log/containers/*_%s_*.log" .Release.Namespace)) -}}
{{- $scheme := ternary "https" "http" (eq (include "imas-farmer.s3UseSSL" .) "true") -}}
{{- $region := ternary .Values.versity.region $l.region (eq (include "imas-farmer.s3UsesVersity" .) "true") -}}
service:
  flush: 5
  log_level: info
  http_server: on
  http_listen: 0.0.0.0
  http_port: 2020
  health_check: on
pipeline:
  inputs:
    - name: tail
      path: {{ join "," $paths | quote }}
      multiline.parser: cri, docker
      tag: kube.*
      read_from_head: true
      db: /var/fluent-bit/tail.db
      mem_buf_limit: 50MB
      skip_long_lines: on
      refresh_interval: 10
  outputs:
    - name: s3
      match: kube.*
      bucket: {{ $l.bucket | quote }}
      region: {{ $region | quote }}
      endpoint: {{ printf "%s://%s" $scheme (include "imas-farmer.s3Endpoint" .) | quote }}
      use_put_object: on
      total_file_size: {{ $l.totalFileSize | quote }}
      upload_timeout: {{ $l.uploadTimeout | quote }}
      compression: gzip
      store_dir: /var/fluent-bit/s3
      # <prefix><YYYY>/<MM>/<DD>/<pod>-<HHMMSS>-<uuid>.gz: the day is what
      # the retention CronJob dates an object by (internal/retention
      # LogDate). $TAG[4] is the pod name of
      # kube.var.log.containers.<pod>_<namespace>_<container>-<id>.log.
      s3_key_format: {{ printf "/%s%%Y/%%m/%%d/$TAG[4]-%%H%%M%%S-$UUID.gz" $l.prefix | quote }}
      s3_key_format_tag_delimiters: "._"
{{- end }}

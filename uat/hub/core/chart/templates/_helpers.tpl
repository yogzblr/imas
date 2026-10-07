{{- define "uat.labels" -}}
app.kubernetes.io/part-of: imas-uat
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
imas.io/uat-only: "true"
{{- end }}

{{- define "uat.coreURL" -}}
{{- if eq (int .Values.core.httpsPort) 443 -}}
https://{{ .Values.core.fqdn }}
{{- else -}}
https://{{ .Values.core.fqdn }}:{{ .Values.core.httpsPort }}
{{- end -}}
{{- end }}

{{- define "uat.validate" -}}
{{- if hasKey .Values.core "exposure" -}}
{{- fail "core.exposure was dropped: the edge always uses hostPorts (owner decision 2026-10-06)" -}}
{{- end -}}
{{- range $k, $v := dict "core.privateIP" .Values.core.privateIP "dmz.privateIP" .Values.dmz.privateIP -}}
{{- if not (regexMatch "^[0-9]{1,3}(\\.[0-9]{1,3}){3}$" $v) -}}
{{- fail (printf "%s must be an IPv4 address" $k) -}}
{{- end -}}
{{- end -}}
{{- if contains "latest" (printf "%s %s %s" .Values.minio.image .Values.keycloak.image .Values.edge.image) -}}
{{- fail "UAT images are pinned: never latest" -}}
{{- end -}}
{{- end }}

{{- define "uat.dnsEgress" -}}
- to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: kube-system
      podSelector:
        matchLabels:
          k8s-app: kube-dns
  ports:
    - { protocol: UDP, port: 53 }
    - { protocol: TCP, port: 53 }
{{- end }}

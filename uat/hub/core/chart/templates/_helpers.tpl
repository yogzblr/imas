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
{{- range $k, $list := dict "core.nodeIPs" .Values.core.nodeIPs "dmz.nodeIPs" .Values.dmz.nodeIPs -}}
{{- range $list -}}
{{- if not (regexMatch "^[0-9]{1,3}(\\.[0-9]{1,3}){3}$" .) -}}
{{- fail (printf "%s must list IPv4 addresses, got %v" $k .) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if and .Values.rustfs.enabled .Values.versity.enabled -}}
{{- fail "rustfs.enabled and versity.enabled: the accounts store port is RustFS's or the edge's (for Versity Gateway), not both" -}}
{{- end -}}
{{- if lt (int .Values.edge.replicas) 1 -}}
{{- fail "edge.replicas must be 1 or more" -}}
{{- end -}}
{{- if contains "latest" (printf "%s %s %s" .Values.rustfs.image .Values.keycloak.image .Values.edge.image) -}}
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

{{/* The addresses the DMZ hub's traffic comes from, as ipBlock peers: each
DMZ node (dmz.nodeIPs; empty: dmz.privateIP, the one node). A DMZ pod's
traffic to this hub leaves through its node's address, whatever address it
was sent to. With loadBalancerProbe.enabled (an HA core hub behind Azure
load balancers) the health probes' source too, so a node whose pod
listens stays in the load balancer's rule. */}}
{{- define "uat.dmzPeers" -}}
{{- range (default (list .Values.dmz.privateIP) .Values.dmz.nodeIPs) }}
- ipBlock: { cidr: {{ printf "%s/32" . }} }
{{- end }}
{{- if .Values.loadBalancerProbe.enabled }}
- ipBlock: { cidr: {{ .Values.loadBalancerProbe.cidr }} }
{{- end }}
{{- end }}

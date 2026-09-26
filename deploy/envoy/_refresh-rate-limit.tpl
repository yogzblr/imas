{{- /*
Reference Helm template for envoy.yaml's POST /v1/refresh route and its
own local_ratelimit bucket, sized from .Values.envoy.refreshRateLimit
(values.rate-limit.yaml). NOT rendered by anything in this repo: copy it
into the ops repo's Envoy chart and include it in the route list of the
Envoy config template, e.g.

  routes:
    {{- include "imas.envoy.refreshRoute" . | nindent 22 }}

See README.md, "Sizing the /v1/refresh bucket", for the math.
*/ -}}
{{- define "imas.envoy.refreshTokensPerFill" -}}
{{- $r := .Values.envoy.refreshRateLimit -}}
{{- if not (kindIs "invalid" $r.tokensPerFill) -}}
{{- if lt (int64 $r.tokensPerFill) 1 -}}{{- fail "envoy.refreshRateLimit.tokensPerFill must be >= 1" -}}{{- end -}}
{{- int64 $r.tokensPerFill -}}
{{- else -}}
{{- range $k := list "fleetSize" "gatewayJwtTtlSeconds" "envoyReplicas" "headroom" "fillIntervalSeconds" -}}
{{- $v := index $r $k -}}
{{- if or (kindIs "invalid" $v) (lt (float64 $v) 1.0) -}}{{- fail (printf "envoy.refreshRateLimit.%s must be set and >= 1" $k) -}}{{- end -}}
{{- if ne (float64 $v) (float64 (int64 $v)) -}}{{- fail (printf "envoy.refreshRateLimit.%s must be a whole number" $k) -}}{{- end -}}
{{- end -}}
{{- /* ceil(fleetSize*30*headroom*fillInterval / (17*ttl*replicas)) */ -}}
{{- $num := mul (int64 $r.fleetSize) 30 (int64 $r.headroom) (int64 $r.fillIntervalSeconds) -}}
{{- $den := mul 17 (int64 $r.gatewayJwtTtlSeconds) (int64 $r.envoyReplicas) -}}
{{- div (sub (add $num $den) 1) $den -}}
{{- end -}}
{{- end -}}

{{- define "imas.envoy.refreshMaxTokens" -}}
{{- $r := .Values.envoy.refreshRateLimit -}}
{{- $perFill := include "imas.envoy.refreshTokensPerFill" . | int64 -}}
{{- if not (kindIs "invalid" $r.maxTokens) -}}
{{- if lt (int64 $r.maxTokens) $perFill -}}{{- fail "envoy.refreshRateLimit.maxTokens must be >= tokensPerFill" -}}{{- end -}}
{{- int64 $r.maxTokens -}}
{{- else -}}
{{- if or (kindIs "invalid" $r.burstSeconds) (lt (int64 $r.burstSeconds) (int64 $r.fillIntervalSeconds)) -}}{{- fail "envoy.refreshRateLimit.burstSeconds must be >= fillIntervalSeconds" -}}{{- end -}}
{{- mul $perFill (div (int64 $r.burstSeconds) (int64 $r.fillIntervalSeconds)) -}}
{{- end -}}
{{- end -}}

{{- define "imas.envoy.refreshRoute" -}}
- match: { path: "/v1/refresh" }
  route:
    cluster: farmer_api
    timeout: 30s
  typed_per_filter_config:
    envoy.filters.http.jwt_authn:
      "@type": type.googleapis.com/envoy.extensions.filters.http.jwt_authn.v3.PerRouteConfig
      disabled: true
    envoy.filters.http.local_ratelimit:
      "@type": type.googleapis.com/envoy.extensions.filters.http.local_ratelimit.v3.LocalRateLimit
      stat_prefix: refresh_rate_limiter
      token_bucket:
        max_tokens: {{ include "imas.envoy.refreshMaxTokens" . }}
        tokens_per_fill: {{ include "imas.envoy.refreshTokensPerFill" . }}
        fill_interval: {{ int64 .Values.envoy.refreshRateLimit.fillIntervalSeconds }}s
      filter_enabled:
        runtime_key: refresh_rate_limit_enabled
        default_value: { numerator: 100, denominator: HUNDRED }
      filter_enforced:
        runtime_key: refresh_rate_limit_enforced
        default_value: { numerator: 100, denominator: HUNDRED }
{{- end -}}

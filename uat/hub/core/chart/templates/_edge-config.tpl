{{/* The edge proxy's Envoy configuration (edge.yaml). */}}
{{- define "uat.edgeEnvoyConfig" -}}
{{- $saasapi := printf "%s.%s.svc.%s" .Values.farmer.saasapiServiceName .Values.farmer.namespace .Values.clusterDomain -}}
{{- $farmer := printf "%s.%s.svc.%s" .Values.farmer.serviceName .Values.farmer.namespace .Values.clusterDomain -}}
{{- $keycloak := printf "imas-uat-keycloak.%s.svc.%s" .Release.Namespace .Values.clusterDomain -}}
static_resources:
  listeners:
    - name: https
      address: { socket_address: { address: 0.0.0.0, port_value: 443 } }
      filter_chains:
        - transport_socket:
            name: envoy.transport_sockets.tls
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
              common_tls_context:
                tls_params: { tls_minimum_protocol_version: TLSv1_2 }
                tls_certificates:
                  - certificate_chain: { filename: /etc/edge-tls/tls.crt }
                    private_key: { filename: /etc/edge-tls/tls.key }
          filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: edge_https
                use_remote_address: true
                normalize_path: true
                merge_slashes: true
                path_with_escaped_slashes_action: REJECT_REQUEST
                common_http_protocol_options:
                  headers_with_underscores_action: REJECT_REQUEST
                route_config:
                  name: core
                  virtual_hosts:
                    - name: core
                      domains: ["*"]
                      routes:
                        - match: { prefix: "/v1/" }
                          route: { cluster: saasapi, timeout: 120s }
                        - match: { prefix: "/realms/{{ .Values.keycloak.realm }}/" }
                          route: { cluster: keycloak, timeout: 60s }
                        - match: { prefix: "/" }
                          direct_response: { status: 404, body: { inline_string: "not found\n" } }
                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
    - name: farmer_api
      address: { socket_address: { address: 0.0.0.0, port_value: {{ .Values.farmer.apiPort }} } }
      filter_chains:
        - filters:
            - name: envoy.filters.network.tcp_proxy
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
                stat_prefix: farmer_api
                cluster: farmer_api
  clusters:
    - name: saasapi
      type: STRICT_DNS
      connect_timeout: 5s
      load_assignment:
        cluster_name: saasapi
        endpoints:
          - lb_endpoints:
              - endpoint: { address: { socket_address: { address: {{ $saasapi }}, port_value: {{ .Values.farmer.saasapiServicePort }} } } }
    - name: keycloak
      type: STRICT_DNS
      connect_timeout: 5s
      load_assignment:
        cluster_name: keycloak
        endpoints:
          - lb_endpoints:
              - endpoint: { address: { socket_address: { address: {{ $keycloak }}, port_value: 8080 } } }
    - name: farmer_api
      type: STRICT_DNS
      connect_timeout: 5s
      load_assignment:
        cluster_name: farmer_api
        endpoints:
          - lb_endpoints:
              - endpoint: { address: { socket_address: { address: {{ $farmer }}, port_value: {{ .Values.farmer.apiPort }} } } }
{{- end }}

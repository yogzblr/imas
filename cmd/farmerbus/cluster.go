package main

// Cluster routes for the DMZ bus (docs/design/imas-1m-scale-plan.md
// Phase 2). FLAG FOR SECURITY REVIEW: the route port carries every
// tenant's traffic and the SYS account's claims updates between bus nodes,
// so it is the one listener on this process that must never accept an
// unauthenticated peer.
//
// A route is admitted only when all of these hold:
//
//   - mutual TLS: the peer presents a certificate that chains to the same
//     root CA the client port trusts (config.RootCA), and the dialing side
//     verifies the listener's certificate against it too;
//   - the peer's certificate names one of the configured route hosts
//     (a DNS or IP SAN), so a certificate the CA issued for some other
//     purpose is not enough on its own;
//   - the CONNECT carries the shared route user and password, read from a
//     file (IMAS_BUS_CLUSTER_ROUTE_PASSWORD_FILE), never from an env var.
//
// Clustering is off unless IMAS_BUS_CLUSTER_ROUTES is set; a partial
// configuration (routes without a port, or without credentials) is a
// startup error rather than a silently unclustered or unauthenticated bus.

import (
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	nats_server "github.com/nats-io/nats-server/v2/server"
)

const (
	envClusterName         = "IMAS_BUS_CLUSTER_NAME"
	envClusterPort         = "IMAS_BUS_CLUSTER_PORT"
	envClusterRoutes       = "IMAS_BUS_CLUSTER_ROUTES"
	envClusterRouteUser    = "IMAS_BUS_CLUSTER_ROUTE_USER"
	envClusterPasswordFile = "IMAS_BUS_CLUSTER_ROUTE_PASSWORD_FILE"
	envClusterAdvertise    = "IMAS_BUS_CLUSTER_ADVERTISE"
	envServerName          = "IMAS_BUS_SERVER_NAME"

	defaultRouteUser = "imas-bus-route"
	// minRoutePasswordLen rejects placeholder passwords. The chart's
	// documented generator (openssl rand -hex 32) gives 64 characters.
	minRoutePasswordLen = 32
)

// clusterConfig is the parsed IMAS_BUS_CLUSTER_* contract the chart
// renders (deploy/helm/nats, README "Clustering").
type clusterConfig struct {
	Name string
	Port int
	// Routes lists every node of the cluster, normally including this one
	// (nats-server ignores the route to itself). Its length is the cluster
	// size the fence's quorum check uses.
	Routes   []*url.URL
	User     string
	Password string
	// Advertise is the host:port this node announces to peers for
	// implicit routes. It should be a name its certificate carries (the
	// pod's headless DNS name); left empty, nats-server announces the pod
	// IP, which peers then fail to verify.
	Advertise string
	// ServerName must be unique per node; nats-server refuses a route
	// from a peer with the same name.
	ServerName string
}

// Size is the configured number of bus nodes.
func (c *clusterConfig) Size() int { return len(c.Routes) }

// clusterConfigFromEnv reads the cluster settings. It returns nil, nil when
// clustering is not configured at all.
func clusterConfigFromEnv(getenv func(string) string, readFile func(string) ([]byte, error)) (*clusterConfig, error) {
	routesRaw := strings.TrimSpace(getenv(envClusterRoutes))
	if routesRaw == "" {
		for _, k := range []string{envClusterName, envClusterPort, envClusterPasswordFile} {
			if getenv(k) != "" {
				return nil, fmt.Errorf("%s is set but %s is empty: set both, or neither for a single-node bus", k, envClusterRoutes)
			}
		}
		return nil, nil
	}
	c := &clusterConfig{
		Name:       strings.TrimSpace(getenv(envClusterName)),
		User:       strings.TrimSpace(getenv(envClusterRouteUser)),
		ServerName: strings.TrimSpace(getenv(envServerName)),
		Advertise:  strings.TrimSpace(getenv(envClusterAdvertise)),
	}
	if c.Advertise != "" {
		if _, _, err := net.SplitHostPort(c.Advertise); err != nil {
			return nil, fmt.Errorf("%s must be host:port, got %q", envClusterAdvertise, c.Advertise)
		}
	}
	if c.Name == "" {
		return nil, fmt.Errorf("%s is required when %s is set", envClusterName, envClusterRoutes)
	}
	portRaw := strings.TrimSpace(getenv(envClusterPort))
	port, err := strconv.Atoi(portRaw)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("%s must be a TCP port, got %q", envClusterPort, portRaw)
	}
	c.Port = port
	seen := map[string]bool{}
	for _, raw := range strings.Split(routesRaw, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		u, err := parseRouteURL(raw)
		if err != nil {
			return nil, err
		}
		if seen[u.Host] {
			return nil, fmt.Errorf("%s lists %s twice", envClusterRoutes, u.Host)
		}
		seen[u.Host] = true
		c.Routes = append(c.Routes, u)
	}
	if len(c.Routes) == 0 {
		return nil, fmt.Errorf("%s has no routes", envClusterRoutes)
	}
	if c.User == "" {
		c.User = defaultRouteUser
	}
	pwFile := strings.TrimSpace(getenv(envClusterPasswordFile))
	if pwFile == "" {
		return nil, fmt.Errorf("%s is required when %s is set: the route listener never runs without credentials", envClusterPasswordFile, envClusterRoutes)
	}
	pw, err := readFile(pwFile)
	if err != nil {
		return nil, fmt.Errorf("reading the route password from %s: %w", pwFile, err)
	}
	c.Password = strings.TrimSpace(string(pw))
	if len(c.Password) < minRoutePasswordLen {
		return nil, fmt.Errorf("the route password in %s is shorter than %d characters", pwFile, minRoutePasswordLen)
	}
	if strings.ContainsAny(c.Password, ":@/ \t\r\n") {
		// It is embedded in each route URL's userinfo.
		return nil, fmt.Errorf("the route password in %s must not contain ':', '@', '/' or whitespace", pwFile)
	}
	if c.ServerName == "" {
		if h, err := os.Hostname(); err == nil {
			c.ServerName = h // the StatefulSet pod name
		}
	}
	return c, nil
}

// parseRouteURL accepts tls://, nats:// and nats-route:// host:port URLs.
// Credentials in the URL are refused: they belong in the password file,
// not in an env var or the ConfigMap that renders it.
func parseRouteURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: bad route URL %q: %w", envClusterRoutes, raw, err)
	}
	switch u.Scheme {
	case "tls", "nats", "nats-route":
	default:
		return nil, fmt.Errorf("%s: route URL %q must use tls://, nats:// or nats-route://", envClusterRoutes, raw)
	}
	if u.User != nil {
		return nil, fmt.Errorf("%s: route URL %q carries credentials; use %s instead", envClusterRoutes, u.Redacted(), envClusterPasswordFile)
	}
	if u.Hostname() == "" || u.Port() == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
		return nil, fmt.Errorf("%s: route URL %q must be scheme://host:port", envClusterRoutes, raw)
	}
	return &url.URL{Scheme: u.Scheme, Host: u.Host}, nil
}

// applyCluster adds the route listener and routes to opts, which must
// already carry the client-port TLS configuration built by
// pki.ConfigureNats: the routes reuse its certificate and root CA.
func applyCluster(opts *nats_server.Options, c *clusterConfig) error {
	if opts.TLSConfig == nil || len(opts.TLSConfig.Certificates) == 0 || opts.TLSConfig.RootCAs == nil {
		return errors.New("cluster routes need the bus TLS certificate and root CA; none configured")
	}
	if err := checkRouteCertUsage(opts.TLSConfig.Certificates[0]); err != nil {
		return err
	}
	if c.ServerName != "" {
		opts.ServerName = c.ServerName
	}
	routeTLS := &tls.Config{
		Certificates: opts.TLSConfig.Certificates,
		// Dialing side: verify the peer's listener against the root CA.
		// ServerName is left empty so nats-server sets it per route from
		// the route URL's host, which the certificate must carry.
		RootCAs: opts.TLSConfig.RootCAs,
		// Listening side: no certificate, no route.
		ClientCAs:  opts.TLSConfig.RootCAs,
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS12,
	}
	hosts := make([]string, 0, len(c.Routes))
	routes := make([]*url.URL, 0, len(c.Routes))
	for _, r := range c.Routes {
		hosts = append(hosts, r.Hostname())
		routes = append(routes, &url.URL{
			Scheme: r.Scheme,
			Host:   r.Host,
			User:   url.UserPassword(c.User, c.Password),
		})
	}
	opts.Cluster = nats_server.ClusterOpts{
		Name:      c.Name,
		Host:      opts.Host,
		Port:      c.Port,
		Username:  c.User,
		Password:  c.Password,
		TLSConfig: routeTLS,
		Advertise: c.Advertise,
		// Matches the client port's 2s default handshake budget with
		// headroom for a loaded node.
		TLSTimeout:  5,
		AuthTimeout: 5,
		// Don't gossip pod addresses to clients. Core reaches the bus
		// through its Service and sprouts through Envoy; neither should
		// learn, or try, a pod IP behind them.
		NoAdvertise: true,
	}
	opts.Routes = routes
	opts.CustomRouterAuthentication = &routeAuth{user: c.User, password: c.Password, hosts: hosts}
	return nil
}

// checkRouteCertUsage fails fast when the node certificate cannot serve
// both ends of a route: each node dials its peers (client) and accepts
// them (server) with the same certificate. An OpenBao PKI role with
// client_flag=false, for one, issues a server-only certificate, and every
// route handshake would then fail with nothing but TLS errors in the log.
func checkRouteCertUsage(cert tls.Certificate) error {
	leaf := cert.Leaf
	if leaf == nil {
		if len(cert.Certificate) == 0 {
			return errors.New("cluster routes: the bus certificate is empty")
		}
		var err error
		if leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
			return fmt.Errorf("cluster routes: parsing the bus certificate: %w", err)
		}
	}
	if len(leaf.ExtKeyUsage) == 0 {
		return nil // no EKU extension: valid for any use
	}
	var client, server bool
	for _, u := range leaf.ExtKeyUsage {
		switch u {
		case x509.ExtKeyUsageAny:
			client, server = true, true
		case x509.ExtKeyUsageClientAuth:
			client = true
		case x509.ExtKeyUsageServerAuth:
			server = true
		}
	}
	if !client || !server {
		return errors.New("cluster routes need a bus certificate with both serverAuth and clientAuth extended key usage (mutual TLS between nodes); reissue it (OpenBao PKI role: client_flag=true)")
	}
	return nil
}

// routeAuth admits an inbound route only with the shared credentials AND a
// verified client certificate naming one of the configured route hosts.
// It replaces nats-server's own user/password check for routes (which a
// custom authenticator bypasses), so it performs that check itself.
type routeAuth struct {
	user, password string
	hosts          []string
}

func (a *routeAuth) Check(c nats_server.ClientAuthentication) bool {
	o := c.GetOpts()
	if o == nil {
		return false
	}
	userOK := subtle.ConstantTimeCompare([]byte(o.Username), []byte(a.user)) == 1
	passOK := subtle.ConstantTimeCompare([]byte(o.Password), []byte(a.password)) == 1
	if !userOK || !passOK {
		return false
	}
	cs := c.GetTLSConnectionState()
	if cs == nil || len(cs.VerifiedChains) == 0 || len(cs.VerifiedChains[0]) == 0 {
		return false
	}
	leaf := cs.VerifiedChains[0][0]
	for _, h := range a.hosts {
		if ip := net.ParseIP(h); ip != nil {
			for _, sanIP := range leaf.IPAddresses {
				if sanIP.Equal(ip) {
					return true
				}
			}
			continue
		}
		if leaf.VerifyHostname(h) == nil {
			return true
		}
	}
	return false
}

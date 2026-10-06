// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package otlp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	appmetrics "github.com/NeuralTrust/TrustGate/pkg/app/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/netguard"
	infratelemetry "github.com/NeuralTrust/TrustGate/pkg/infra/telemetry"
)

var _ infratelemetry.TenantExporterTemplate = (*Template)(nil)

// errTenantTLSFiles is deliberately the same for a path that exists and one that
// does not: the settings come from a tenant, and a message that differs by file
// would tell them what is on the gateway pod.
var errTenantTLSFiles = errors.New("otlp: tls file paths cannot be set in gateway settings; use tls.skip_verify or ask the operator to configure the collector")

// ValidateTenantConfig validates settings a tenant wrote into a gateway.
func (t *Template) ValidateTenantConfig(settings map[string]interface{}) error {
	_, err := t.tenantSettings(settings)
	return err
}

// WithTenantSettings builds an exporter from settings a tenant wrote. A tenant
// that names its own endpoint is dialled through the netguard dialer, so the
// collector it points at must be a public address.
func (t *Template) WithTenantSettings(settings map[string]interface{}) (appmetrics.Exporter, error) {
	s, err := t.tenantSettings(settings)
	if err != nil {
		return nil, err
	}
	provider, err := newLoggerProvider(context.Background(), s)
	if err != nil {
		return nil, err
	}
	return newExporterWithProvider(provider, t.logger, s.Timeout), nil
}

// tenantSettings parses and checks tenant settings.
//
// TLS file paths are refused outright on a shared gateway (when the operator has
// not set OUTBOUND_ALLOW_PRIVATE_NETWORKS). Whatever a tenant can name must be
// on the pod's filesystem, and the pod's files belong to the operator: the
// existence check, the parse error and the load itself would each tell a tenant
// something about them, and the only files a tenant could legitimately mean are
// ones they have no way to place there. An operator who needs mutual TLS to a
// collector configures it through the environment, which is not tenant input.
// A self-hosted gateway, where the tenant is the operator, keeps file paths.
func (t *Template) tenantSettings(raw map[string]interface{}) (Settings, error) {
	s, err := parseSettings(raw, t.envCfg)
	if err != nil {
		return Settings{}, err
	}
	if netguard.AllowPrivate() {
		return s, s.validate()
	}
	// Provenance comes from the decoded value: mapstructure matches "Endpoint"
	// and "ENDPOINT" too, so a lookup of the lowercase key in raw would miss them.
	supplied, err := decodeSettings(raw)
	if err != nil {
		return Settings{}, err
	}
	if supplied.TLS != nil && (supplied.TLS.CAFile != "" || supplied.TLS.CertFile != "" || supplied.TLS.KeyFile != "") {
		return Settings{}, errTenantTLSFiles
	}
	if strings.TrimSpace(supplied.Endpoint) == "" {
		// The endpoint is the operator's collector, so everything that decides
		// how it is reached is the operator's too: a tenant must not add
		// headers to it, turn TLS off, skip verification or switch protocol.
		// Compression, timeout and body limit are the tenant's to tune.
		inherited, err := parseSettings(nil, t.envCfg)
		if err != nil {
			return Settings{}, err
		}
		if supplied.Compression != "" {
			inherited.Compression = supplied.Compression
		}
		if supplied.Timeout != 0 {
			inherited.Timeout = supplied.Timeout
		}
		if supplied.MaxBodyBytes > 0 {
			inherited.MaxBodyBytes = supplied.MaxBodyBytes
		}
		return inherited, inherited.validateShape()
	}
	// The tenant names its own collector, so nothing of the operator's may ride
	// along: not the OTEL_EXPORTER_OTLP_HEADERS credentials, not the operator's
	// insecure flag or protocol. Only operator-neutral defaults fill the gaps.
	own := supplied
	own.Endpoint = strings.TrimSpace(supplied.Endpoint)
	if own.Protocol == "" {
		own.Protocol = resolveProtocol(own.Endpoint)
	}
	if own.Signal == "" {
		own.Signal = defaultSignal
	}
	if own.Timeout == 0 {
		own.Timeout = defaultTimeout
	}
	if own.Compression == "" {
		own.Compression = defaultCompression
	}
	if own.MaxBodyBytes <= 0 {
		own.MaxBodyBytes = defaultMaxBodyBytes
	}
	if err := own.validateShape(); err != nil {
		return Settings{}, err
	}
	if err := validateTenantEndpoint(own.Endpoint); err != nil {
		return Settings{}, err
	}
	// A tenant endpoint is always a full URL, so the scheme (not a process env
	// var) decides whether the connection is encrypted. A bare host is https
	// unless the tenant asked for insecure.
	own.Endpoint = tenantEndpointURL(own.Endpoint, own.Insecure)
	if u, err := url.Parse(own.Endpoint); err == nil {
		own.Insecure = strings.EqualFold(u.Scheme, "http")
	}
	own.guarded = true
	return own, nil
}

// tenantEndpointURL returns endpoint as a URL with a scheme.
func tenantEndpointURL(endpoint string, insecure bool) string {
	if hasScheme(endpoint) {
		return endpoint
	}
	if insecure {
		return "http://" + endpoint
	}
	return "https://" + endpoint
}

// validateTenantEndpoint rejects, at write time and without any lookup, the
// endpoints that can never be right: a scheme other than http(s), no host,
// embedded credentials, and a literal loopback, private or link-local address.
// A hostname that merely resolves to one is caught at dial time.
func validateTenantEndpoint(endpoint string) error {
	endpoint = strings.TrimSpace(endpoint)
	candidate := endpoint
	if !hasScheme(candidate) {
		candidate = "//" + candidate
	}
	u, err := url.Parse(candidate)
	if err != nil {
		return errors.New("otlp: endpoint is not a valid URL or host:port")
	}
	switch u.Scheme {
	case "", "http", "https":
	default:
		return fmt.Errorf("otlp: endpoint scheme %q is not supported (want http or https)", u.Scheme)
	}
	if u.User != nil {
		return errors.New("otlp: endpoint must not carry credentials; use headers")
	}
	host := u.Hostname()
	if host == "" {
		return errors.New("otlp: endpoint has no host")
	}
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
		return errors.New("otlp: endpoint must be a public address")
	}
	if ip := net.ParseIP(host); ip != nil && !netguard.IsPublicUnicast(ip) {
		return errors.New("otlp: endpoint must be a public address")
	}
	return nil
}

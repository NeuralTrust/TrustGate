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

package postgres

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/url"
	"strings"

	appmetrics "github.com/NeuralTrust/TrustGate/pkg/app/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/netguard"
	infratelemetry "github.com/NeuralTrust/TrustGate/pkg/infra/telemetry"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var _ infratelemetry.TenantExporterTemplate = (*Template)(nil)

// ValidateTenantConfig validates settings a tenant wrote into a gateway.
func (t *Template) ValidateTenantConfig(settings map[string]interface{}) error {
	s, err := parseSettings(settings)
	if err != nil {
		return err
	}
	if err := s.validate(); err != nil {
		return err
	}
	return s.validateTenant()
}

// WithTenantSettings builds an exporter from settings a tenant wrote. A literal
// dsn is dialled through the netguard dialer.
func (t *Template) WithTenantSettings(settings map[string]interface{}) (appmetrics.Exporter, error) {
	return t.withSettings(settings, true)
}

// tenantDSNKeys is everything a tenant's literal DSN may say. It is an
// allow-list enforced by pgx's own parser, so it holds for every spelling the
// parser accepts (quoting, escapes, URL or keyword form) and fails closed for
// any parameter pgx learns later. File-reading parameters (sslrootcert, sslkey,
// passfile, service, servicefile...) are simply not in it.
var tenantDSNKeys = []string{
	"host", "port", "user", "password", "dbname", "database", "sslmode",
	"connect_timeout", "application_name", "target_session_attrs",
}

var errTenantDSN = errors.New("postgres: dsn is invalid or uses parameters that are not allowed in gateway settings")

// validateTenant restricts what a tenant may ask the exporter to connect to.
//
//   - dsn_env names an environment variable of the gateway process, and the
//     exporter connects with whatever it holds: a tenant naming DATABASE_URL
//     would make the gateway log in to the operator's own database and write
//     telemetry rows into it. It is an operator setting and is refused.
//   - A literal dsn is the tenant's own database, so it stays allowed, but it is
//     a connection the gateway opens to a tenant-chosen host. It is parsed with
//     an allow-list of keys, may not name a unix socket, and is dialled through
//     netguard (see openGuardedPool).
//
// A self-hosted gateway, where the tenant is the operator, is not restricted
// (OUTBOUND_ALLOW_PRIVATE_NETWORKS). A tenant exporter with no dsn at all keeps
// resolving to the operator's own database, which is existing behaviour.
func (s Settings) validateTenant() error {
	if netguard.AllowPrivate() {
		return nil
	}
	if strings.TrimSpace(s.DSNEnv) != "" {
		return errors.New("postgres: dsn_env is an operator setting and cannot be set in gateway settings")
	}
	if dsn := strings.TrimSpace(s.DSN); dsn != "" {
		if _, err := parseTenantDSN(dsn); err != nil {
			return errTenantDSN
		}
	}
	return nil
}

// parseTenantDSN parses a tenant DSN and strips what pgx merges in from the
// gateway pod: the password from PGPASSWORD or ~/.pgpass when the DSN carries
// none, and TLS material loaded from PGSSL* files. Hosts must be network hosts.
func parseTenantDSN(dsn string) (*pgxpool.Config, error) {
	// Validate with pgx's own parser first: a key outside the allow-list is
	// rejected before any file is touched.
	if _, err := pgconn.ParseConfigWithOptions(dsn, pgconn.ParseConfigOptions{ConnStringAllowedKeys: tenantDSNKeys}); err != nil {
		return nil, err
	}
	conf, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	cc := conf.ConnConfig
	if !passwordIsInDSN(dsn, cc.Password) {
		cc.Password = ""
	}
	hosts := []string{cc.Host}
	for _, fb := range cc.Fallbacks {
		hosts = append(hosts, fb.Host)
	}
	for _, h := range hosts {
		if strings.HasPrefix(h, "/") || strings.HasPrefix(h, "@") {
			return nil, errTenantDSN
		}
	}
	cc.TLSConfig = withoutFileTLS(cc.TLSConfig)
	for _, fb := range cc.Fallbacks {
		fb.TLSConfig = withoutFileTLS(fb.TLSConfig)
	}
	if conf.MaxConns > telemetryMaxConns {
		conf.MaxConns = telemetryMaxConns
	}
	return conf, nil
}

// passwordIsInDSN reports whether the password pgx resolved was written in the
// DSN rather than inherited from PGPASSWORD or a passfile. It errs towards
// "inherited", which only costs a tenant with an unusual password a failed login.
func passwordIsInDSN(dsn, password string) bool {
	if password == "" {
		return false
	}
	if u, err := url.Parse(dsn); err == nil && u.User != nil {
		if pw, ok := u.User.Password(); ok && pw == password {
			return true
		}
	}
	candidates := []string{
		password,
		strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(password),
		url.QueryEscape(password),
	}
	for _, c := range candidates {
		if strings.Contains(dsn, c) {
			return true
		}
	}
	return false
}

// withoutFileTLS drops client certificates and root CAs that pgx loaded from
// files named by PGSSLCERT, PGSSLKEY or PGSSLROOTCERT in the pod environment.
func withoutFileTLS(c *tls.Config) *tls.Config {
	if c == nil {
		return nil
	}
	c = c.Clone()
	c.Certificates = nil
	c.RootCAs = nil
	c.GetClientCertificate = nil
	return c
}

// openGuardedPool opens a pool whose every connection, fallback hosts included,
// is dialled through the shared netguard dialer.
func openGuardedPool(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	conf, err := parseTenantDSN(dsn)
	if err != nil {
		return nil, errTenantDSN
	}
	conf.ConnConfig.DialFunc = netguard.Shared().DialContext
	pool, err := pgxpool.NewWithConfig(ctx, conf)
	if err != nil {
		return nil, fmt.Errorf("postgres: open pool: %w", err)
	}
	return pool, nil
}

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

var errTenantVerifyCA = errors.New("postgres: sslmode=verify-ca (or require with a root CA configured on the gateway) is not supported in gateway settings; use verify-full")

// noPassfile is a path nothing exists at, so pgx finds no stored password.
const noPassfile = "/nonexistent/trustgate-no-passfile"

// sslmodeIfOmitted is the libpq default, applied only when the DSN has no
// sslmode of its own, so PGSSLMODE in the pod environment never picks it.
func sslmodeIfOmitted(dsn string) string {
	if dsnOmitsKey(dsn, "sslmode") {
		return "prefer"
	}
	return ""
}

// withParam adds key=value to a DSN that has already passed the allow-list (so
// it does not contain the key and is well formed). An empty value is a no-op.
func withParam(dsn, key, value string) string {
	if value == "" {
		return dsn
	}
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		sep := "?"
		if strings.Contains(dsn, "?") {
			sep = "&"
		}
		return dsn + sep + key + "=" + url.QueryEscape(value)
	}
	return dsn + " " + key + "=" + value
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
			return publicDSNError(err)
		}
	}
	return nil
}

// publicDSNError is the error a tenant sees: the specific verify-ca message, or
// a generic one that never echoes the DSN or what pgx found on the pod.
func publicDSNError(err error) error {
	if errors.Is(err, errTenantVerifyCA) {
		return errTenantVerifyCA
	}
	return errTenantDSN
}

// parseTenantDSN parses a tenant DSN and strips what pgx merges in from the
// gateway pod: the password from PGPASSWORD or ~/.pgpass when the DSN carries
// none, and TLS material loaded from PGSSL* files. Hosts must be written in the
// DSN and be network hosts.
func parseTenantDSN(dsn string) (*pgxpool.Config, error) {
	// Validate with pgx's own parser first: a key outside the allow-list is
	// rejected before the parser reads any file the DSN itself names. Files named
	// by the pod environment (PGSSLROOTCERT...) are still read by pgx at parse;
	// that environment is the operator's, and the result is discarded below.
	if _, err := pgconn.ParseConfigWithOptions(dsn, pgconn.ParseConfigOptions{ConnStringAllowedKeys: tenantDSNKeys}); err != nil {
		return nil, err
	}
	// A host the DSN does not write would come from PGHOST: the operator's
	// environment must not decide where a tenant connection goes.
	if dsnOmitsKey(dsn, "host") {
		return nil, errTenantDSN
	}
	// Pin what pgx would otherwise take from the pod: a passfile (PGPASSFILE or
	// ~/.pgpass, looked up even for an explicitly empty password) and, when the
	// DSN says nothing, sslmode (PGSSLMODE). The values come from this package,
	// never from the environment or the tenant.
	conf, err := pgxpool.ParseConfig(withParam(withParam(dsn, "passfile", noPassfile), "sslmode", sslmodeIfOmitted(dsn)))
	if err != nil {
		return nil, err
	}
	cc := conf.ConnConfig
	if dsnOmitsKey(dsn, "password") {
		cc.Password = ""
	}
	// Anything the DSN did not write but PG* variables supplied is not the
	// tenant's to use against its own host.
	if dsnOmitsKey(dsn, "user") {
		cc.User = ""
	}
	if dsnOmitsKey(dsn, "dbname") {
		cc.Database = ""
	}
	delete(cc.RuntimeParams, "options")
	if dsnOmitsKey(dsn, "application_name") {
		delete(cc.RuntimeParams, "application_name")
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
	var tlsErr error
	if cc.TLSConfig, tlsErr = withoutFileTLS(cc.TLSConfig); tlsErr != nil {
		return nil, tlsErr
	}
	for _, fb := range cc.Fallbacks {
		if fb.TLSConfig, tlsErr = withoutFileTLS(fb.TLSConfig); tlsErr != nil {
			return nil, tlsErr
		}
	}
	if conf.MaxConns > telemetryMaxConns {
		conf.MaxConns = telemetryMaxConns
	}
	return conf, nil
}

// dsnOmitsKey reports whether the DSN itself does not write key. It asks pgx's
// own parser, with the key removed from the allow-list, rather than searching
// the text: a substring search can be steered by the value of another parameter.
func dsnOmitsKey(dsn, key string) bool {
	allowed := make([]string, 0, len(tenantDSNKeys))
	for _, k := range tenantDSNKeys {
		// dbname and database are one key to pgx.
		if k == key || (key == "dbname" && k == "database") || (key == "database" && k == "dbname") {
			continue
		}
		allowed = append(allowed, k)
	}
	_, err := pgconn.ParseConfigWithOptions(dsn, pgconn.ParseConfigOptions{ConnStringAllowedKeys: allowed})
	return err == nil
}

// withoutFileTLS drops client certificates and root CAs that pgx loaded from
// files named by PGSSLCERT, PGSSLKEY or PGSSLROOTCERT in the pod environment, so
// verification uses the system pool. sslmode=verify-ca is refused: pgx verifies
// it with a closure that captured the original root CAs, which cannot be
// replaced after the fact. verify-full, require and the rest are unaffected.
func withoutFileTLS(c *tls.Config) (*tls.Config, error) {
	if c == nil {
		return nil, nil
	}
	if c.VerifyPeerCertificate != nil {
		return nil, errTenantVerifyCA
	}
	c = c.Clone()
	c.Certificates = nil
	c.RootCAs = nil
	c.GetClientCertificate = nil
	return c, nil
}

// openGuardedPool opens a pool whose every connection, fallback hosts included,
// is dialled through the shared netguard dialer.
func openGuardedPool(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	var (
		conf *pgxpool.Config
		err  error
	)
	if netguard.AllowPrivate() {
		// Self-hosted: the tenant is the operator, so the DSN keeps every pgx
		// feature (sslrootcert, options, PG* defaults). Only the dial is guarded,
		// and the guard itself lets private addresses through in this mode.
		conf, err = pgxpool.ParseConfig(dsn)
	} else {
		conf, err = parseTenantDSN(dsn)
	}
	if err != nil {
		if netguard.AllowPrivate() {
			return nil, fmt.Errorf("postgres: open pool: %w", err)
		}
		return nil, publicDSNError(err)
	}
	conf.ConnConfig.DialFunc = netguard.Shared().DialContext
	pool, err := pgxpool.NewWithConfig(ctx, conf)
	if err != nil {
		return nil, fmt.Errorf("postgres: open pool: %w", err)
	}
	return pool, nil
}

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
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	appmetrics "github.com/NeuralTrust/TrustGate/pkg/app/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/netguard"
	infratelemetry "github.com/NeuralTrust/TrustGate/pkg/infra/telemetry"
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

// libpq parameters that make the client read a file from the gateway pod.
var dsnFileParams = map[string]struct{}{
	"sslrootcert": {}, "sslcert": {}, "sslkey": {}, "sslpassword": {}, "sslcrl": {},
	"passfile": {}, "service": {}, "servicefile": {},
}

var dsnKeyword = regexp.MustCompile(`(?:^|\s)([A-Za-z_]+)\s*=`)

// validateTenant restricts what a tenant may ask the exporter to connect to.
//
//   - dsn_env names an environment variable of the gateway process, and the
//     exporter connects with whatever it holds: a tenant naming DATABASE_URL
//     would make the gateway log in to the operator's own database and write
//     telemetry rows into it. It is an operator setting and is refused.
//   - A literal dsn is the tenant's own database, so it stays allowed, but it is
//     a connection the gateway opens to a tenant-chosen host. It is dialled
//     through netguard (see openGuardedPool); here it is also refused when it
//     names a unix socket or a libpq parameter that reads a file from the pod.
//
// A self-hosted gateway, where the tenant is the operator, is not restricted
// (OUTBOUND_ALLOW_PRIVATE_NETWORKS).
func (s Settings) validateTenant() error {
	if netguard.AllowPrivate() {
		return nil
	}
	if strings.TrimSpace(s.DSNEnv) != "" {
		return errors.New("postgres: dsn_env is an operator setting and cannot be set in gateway settings")
	}
	dsn := strings.TrimSpace(s.DSN)
	if dsn == "" {
		return nil
	}
	for _, key := range dsnParamKeys(dsn) {
		if _, bad := dsnFileParams[strings.ToLower(key)]; bad {
			return errors.New("postgres: dsn parameters that read files are not allowed in gateway settings")
		}
	}
	if dsnNamesUnixSocket(dsn) {
		return errors.New("postgres: dsn must name a network host, not a unix socket")
	}
	return nil
}

func dsnParamKeys(dsn string) []string {
	var keys []string
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		if u, err := url.Parse(dsn); err == nil {
			for k := range u.Query() {
				keys = append(keys, k)
			}
		}
		return keys
	}
	for _, m := range dsnKeyword.FindAllStringSubmatch(dsn, -1) {
		keys = append(keys, m[1])
	}
	return keys
}

func dsnNamesUnixSocket(dsn string) bool {
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err != nil {
			// An authority Go cannot parse (a percent-encoded socket path, for
			// one) is not a host name worth connecting to.
			return true
		}
		return strings.HasPrefix(u.Host, "/") || strings.HasPrefix(u.Query().Get("host"), "/") ||
			strings.HasPrefix(u.Hostname(), "%2F") || strings.HasPrefix(strings.ToLower(u.Host), "%2f")
	}
	for _, m := range regexp.MustCompile(`host\s*=\s*'?([^\s']*)`).FindAllStringSubmatch(dsn, -1) {
		if strings.HasPrefix(m[1], "/") {
			return true
		}
	}
	return false
}

// openGuardedPool opens a pool whose every connection, fallback hosts included,
// is dialled through the shared netguard dialer.
func openGuardedPool(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	conf, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("postgres: open pool: %w", err)
	}
	conf.ConnConfig.DialFunc = netguard.Shared().DialContext
	pool, err := pgxpool.NewWithConfig(ctx, conf)
	if err != nil {
		return nil, fmt.Errorf("postgres: open pool: %w", err)
	}
	return pool, nil
}

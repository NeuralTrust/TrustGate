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
	"fmt"
	"os"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/metrics"
	"github.com/mitchellh/mapstructure"
)

// ExporterName is the registered name of the postgres exporter template. It is
// the only sink allowed to carry sensible data.
const ExporterName = "postgres"

const defaultDSNEnv = "SENSIBLE_PG_DSN"

// Settings is the per-gateway configuration for the postgres exporter, decoded
// from the telemetry exporter Settings map.
//
// Connection precedence (first match wins):
//  1. literal dsn — local development only
//  2. dsn_env — env var holding a pre-built DSN (legacy chart path)
//  3. SENSIBLE_PG_DSN, when neither dsn nor dsn_env is set
//  4. the service's own DatabaseConfig — discrete DB_* / POSTGRES_LOGIN parts
//
// A postgres exporter can omit settings entirely. Hybrid pods that do not set
// SENSIBLE_PG_DSN still fall through to (4) (RUN-1086).
type Settings struct {
	DSN    string `mapstructure:"dsn"`
	DSNEnv string `mapstructure:"dsn_env"`
	// Table is validated against the module-owned table name; it is an explicit,
	// forward-compatible knob and is not allowed to point anywhere else.
	Table string `mapstructure:"table"`
}

func parseSettings(raw map[string]interface{}) (Settings, error) {
	var s Settings
	if len(raw) > 0 {
		if err := mapstructure.Decode(raw, &s); err != nil {
			return Settings{}, fmt.Errorf("postgres: invalid settings: %w", err)
		}
	}
	if s.Table == "" {
		s.Table = metrics.TableName
	}
	return s, nil
}

func (s Settings) validate() error {
	if s.Table != metrics.TableName {
		return fmt.Errorf("postgres: table %q is not the owned sensible table %q", s.Table, metrics.TableName)
	}
	return nil
}

func (s Settings) hasDSNSource() bool {
	return strings.TrimSpace(s.DSN) != "" || strings.TrimSpace(s.DSNEnv) != ""
}

// resolveDSN prefers a literal dsn (dev only); otherwise it reads dsn_env, then
// SENSIBLE_PG_DSN. An empty result means the template should fall back to
// DatabaseConfig.
func (s Settings) resolveDSN() (string, error) {
	if dsn := strings.TrimSpace(s.DSN); dsn != "" {
		return dsn, nil
	}
	name := strings.TrimSpace(s.DSNEnv)
	if name == "" {
		if dsn := strings.TrimSpace(os.Getenv(defaultDSNEnv)); dsn != "" {
			return dsn, nil
		}
		return "", fmt.Errorf("postgres: resolveDSN called with neither dsn nor dsn_env")
	}
	dsn := strings.TrimSpace(os.Getenv(name))
	if dsn == "" {
		return "", fmt.Errorf("postgres: env var %q referenced by dsn_env is unset or empty", name)
	}
	return dsn, nil
}

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
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/metrics"
	"github.com/mitchellh/mapstructure"
)

// ExporterName is the registered name of the postgres exporter template. It is
// the only sink allowed to carry sensible data.
const ExporterName = "postgres"

// Settings is the per-gateway configuration for the postgres exporter, decoded
// from the telemetry exporter Settings map. The DSN is referenced by env-var
// name so secrets stay out of the config file; a literal dsn is accepted for
// local development only.
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
	if strings.TrimSpace(s.DSN) == "" && strings.TrimSpace(s.DSNEnv) == "" {
		return errors.New("postgres: one of settings.dsn or settings.dsn_env is required")
	}
	if s.Table != metrics.TableName {
		return fmt.Errorf("postgres: table %q is not the owned sensible table %q", s.Table, metrics.TableName)
	}
	return nil
}

// resolveDSN prefers a literal dsn (dev only); otherwise it reads the env var
// named by dsn_env so secrets stay out of the config file.
func (s Settings) resolveDSN() (string, error) {
	if dsn := strings.TrimSpace(s.DSN); dsn != "" {
		return dsn, nil
	}
	name := strings.TrimSpace(s.DSNEnv)
	dsn := strings.TrimSpace(os.Getenv(name))
	if dsn == "" {
		return "", fmt.Errorf("postgres: env var %q referenced by dsn_env is unset or empty", name)
	}
	return dsn, nil
}

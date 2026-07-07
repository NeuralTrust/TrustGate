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
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/metrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSettingsDefaultsTable(t *testing.T) {
	t.Parallel()

	s, err := parseSettings(map[string]interface{}{"dsn_env": "SENSIBLE_PG_DSN"})
	require.NoError(t, err)
	assert.Equal(t, metrics.TableName, s.Table)
	assert.Equal(t, "SENSIBLE_PG_DSN", s.DSNEnv)
}

func TestValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		s       Settings
		wantErr string
	}{
		{"dsn_env accepted", Settings{DSNEnv: "SENSIBLE_PG_DSN", Table: metrics.TableName}, ""},
		{"literal dsn accepted", Settings{DSN: "postgres://localhost/db", Table: metrics.TableName}, ""},
		{"neither dsn nor dsn_env", Settings{Table: metrics.TableName}, "dsn"},
		{"foreign table rejected", Settings{DSNEnv: "SENSIBLE_PG_DSN", Table: "other_table"}, "owned"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.s.validate()
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestResolveDSNPrefersLiteral(t *testing.T) {
	got, err := Settings{DSN: "postgres://literal", DSNEnv: "IGNORED"}.resolveDSN()
	require.NoError(t, err)
	assert.Equal(t, "postgres://literal", got)
}

func TestResolveDSNReadsEnv(t *testing.T) {
	t.Setenv("SENSIBLE_PG_TEST_ENV", "postgres://from-env")
	got, err := Settings{DSNEnv: "SENSIBLE_PG_TEST_ENV"}.resolveDSN()
	require.NoError(t, err)
	assert.Equal(t, "postgres://from-env", got)
}

func TestResolveDSNMissingEnvFails(t *testing.T) {
	_, err := Settings{DSNEnv: "SENSIBLE_PG_DSN_DOES_NOT_EXIST"}.resolveDSN()
	require.Error(t, err)
}

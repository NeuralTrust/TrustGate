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

package config

import (
	stderrors "errors"
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/common/errors"
)

func TestParsePostgresLogin(t *testing.T) {
	tests := []struct {
		name    string
		in      PostgresLogin
		want    PostgresLogin
		wantErr bool
	}{
		{name: "empty defaults to default", in: "", want: PostgresLoginDefault},
		{name: "whitespace defaults to default", in: " \t ", want: PostgresLoginDefault},
		{name: "default is trimmed and lowercased", in: " DeFaUlT ", want: PostgresLoginDefault},
		{name: "aws is trimmed and lowercased", in: " AwS ", want: PostgresLoginAWS},
		{name: "unknown is rejected", in: " iam ", wantErr: true},
		{name: "azure is trimmed and lowercased", in: " AZURE ", want: PostgresLoginAzure},
		{name: "unsupported cloud is rejected", in: "gcp", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParsePostgresLogin(tc.in)
			if tc.wantErr {
				if !stderrors.Is(err, errors.ErrInvalidConfig) || !strings.Contains(err.Error(), "POSTGRES_LOGIN") {
					t.Fatalf("ParsePostgresLogin(%q) error = %v, want ErrInvalidConfig naming POSTGRES_LOGIN", tc.in, err)
				}
				for _, supported := range postgresLogins {
					if !strings.Contains(err.Error(), string(supported)) {
						t.Errorf("error %q must list the supported value %q", err, supported)
					}
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("ParsePostgresLogin(%q) = %q, %v, want %q, nil", tc.in, got, err, tc.want)
			}
		})
	}
}

func TestPostgresLoginUsesTokenAuth(t *testing.T) {
	for login, want := range map[PostgresLogin]bool{"": false, PostgresLoginDefault: false, PostgresLoginAWS: true, PostgresLoginAzure: true} {
		if got := login.UsesTokenAuth(); got != want {
			t.Errorf("PostgresLogin(%q).UsesTokenAuth() = %t, want %t", login, got, want)
		}
	}
}

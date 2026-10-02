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
	"net"
	"sync/atomic"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/netguard/netguardtest"
	"github.com/stretchr/testify/require"
)

// DATABASE_URL stands for any operator env var that holds credentials.
func TestTenantSettings_DSNEnvIsOperatorOnly(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://operator:secret@db.internal:5432/app")
	tpl := NewTemplate(testLogger(), nil)
	settings := map[string]interface{}{"dsn_env": "DATABASE_URL"}

	t.Run("refused for a tenant on a shared gateway", func(t *testing.T) {
		netguardtest.Deny(t)
		err := tpl.ValidateTenantConfig(settings)
		require.ErrorContains(t, err, "dsn_env is an operator setting")
		_, err = tpl.WithTenantSettings(settings)
		require.ErrorContains(t, err, "dsn_env is an operator setting")
	})

	t.Run("still valid for the operator", func(t *testing.T) {
		netguardtest.Deny(t)
		require.NoError(t, tpl.ValidateConfig(settings))
	})

	t.Run("a self-hosted gateway is not restricted", func(t *testing.T) {
		netguardtest.Allow(t)
		require.NoError(t, tpl.ValidateTenantConfig(settings))
	})
}

func TestTenantSettings_LiteralDSNShape(t *testing.T) {
	netguardtest.Deny(t)
	tpl := NewTemplate(testLogger(), nil)
	tests := []struct {
		name    string
		dsn     string
		wantErr bool
	}{
		{"network host", "postgres://u:p@db.example.com:5432/app?sslmode=require", false},
		{"keyword form", "host=db.example.com user=u password=p dbname=app", false},
		{"sslrootcert reads a pod file", "postgres://u:p@db.example.com/app?sslrootcert=/etc/ssl/x", true},
		{"sslkey keyword form", "host=db.example.com sslkey=/var/run/secrets/key", true},
		{"passfile", "postgres://u@db.example.com/app?passfile=/root/.pgpass", true},
		{"service file", "service=prod", true},
		{"unix socket url", "postgres://u:p@%2Fvar%2Frun%2Fpostgresql/app", true},
		{"unix socket keyword", "host=/var/run/postgresql user=u", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tpl.ValidateTenantConfig(map[string]interface{}{"dsn": tt.dsn})
			if tt.wantErr {
				require.Error(t, err)
				require.NotContains(t, err.Error(), tt.dsn, "the error must not echo the DSN")
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// A literal DSN is a connection to a tenant-chosen host; on a shared gateway the
// dialer must refuse an internal one before any byte is sent.
func TestTenantSettings_LiteralDSNDialIsGuarded(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = lis.Close() })
	var accepted atomic.Int32
	go func() {
		for {
			c, aerr := lis.Accept()
			if aerr != nil {
				return
			}
			accepted.Add(1)
			_ = c.Close()
		}
	}()
	dsn := fmt.Sprintf("postgres://u:p@%s/app?sslmode=disable", lis.Addr().String())
	settings := map[string]interface{}{"dsn": dsn}
	tpl := NewTemplate(testLogger(), nil)

	netguardtest.Deny(t)
	_, err = tpl.WithTenantSettings(settings)
	require.Error(t, err)
	require.Zero(t, accepted.Load(), "the tenant DSN must never reach an internal host")

	// Positive control: the operator's own DSN is not guarded.
	_, err = tpl.WithSettings(settings)
	require.Error(t, err, "the stub is not a database, so the build still fails")
	require.NotZero(t, accepted.Load())
}

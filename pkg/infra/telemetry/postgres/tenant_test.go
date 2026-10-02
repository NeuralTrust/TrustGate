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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/infra/netguard"
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
		{"quote-adjacent sslrootcert", "host=db.example.com password='x'sslrootcert=/etc/hostname", true},
		{"quote-adjacent sslkey after user", "host=db.example.com user='u'sslkey=/etc/hostname", true},
		{"upper-case key", "host=db.example.com SSLROOTCERT=/etc/hostname", true},
		{"url form sslcert", "postgres://u:p@db.example.com/app?SslCert=/etc/hostname", true},
		{"unknown runtime parameter", "postgres://u:p@db.example.com/app?options=-c%20x", true},
		{"unix socket fallback host", "postgres://u:p@db.example.com,%2Fvar%2Frun%2Fpostgresql/app", true},
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

// A tenant DSN without a password must not pick up the operator's from the
// environment or a passfile, or a host the tenant owns could collect it.
func TestParseTenantDSN_DoesNotInheritOperatorCredentials(t *testing.T) {
	t.Setenv("PGPASSWORD", "operator-secret")

	conf, err := parseTenantDSN("postgres://u@db.example.com/app")
	require.NoError(t, err)
	require.Empty(t, conf.ConnConfig.Password)

	conf, err = parseTenantDSN("host=db.example.com user=u password='it\\'s'")
	require.NoError(t, err)
	require.Equal(t, "it's", conf.ConnConfig.Password, "a password the tenant wrote is kept")

	conf, err = parseTenantDSN("postgres://u:mine@db.example.com/app")
	require.NoError(t, err)
	require.Equal(t, "mine", conf.ConnConfig.Password)
}

// A tenant exporter with no settings is the operator's own database (existing
// behaviour); it must not be dialled through the tenant guard.
func TestTenantSettings_NoDSNStaysOnTheOperatorPath(t *testing.T) {
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
	t.Setenv("SENSIBLE_PG_DSN", fmt.Sprintf("postgres://u:p@%s/app?sslmode=disable", lis.Addr().String()))
	netguardtest.Deny(t)

	_, err = NewTemplate(testLogger(), nil).WithTenantSettings(map[string]interface{}{})
	require.Error(t, err, "the stub is not a database")
	require.NotErrorIs(t, err, netguard.ErrBlockedDestination)
	require.NotZero(t, accepted.Load(), "the operator DSN must reach the dial")
}

func TestTenantSettings_KeyCaseDoesNotHideOperatorOnlySettings(t *testing.T) {
	netguardtest.Deny(t)
	tpl := NewTemplate(testLogger(), nil)
	for _, key := range []string{"dsn_env", "Dsn_Env", "DSN_ENV"} {
		require.ErrorContains(t, tpl.ValidateTenantConfig(map[string]interface{}{key: "DATABASE_URL"}), "dsn_env is an operator setting", key)
	}
	for _, key := range []string{"dsn", "DSN", "Dsn"} {
		require.Error(t, tpl.ValidateTenantConfig(map[string]interface{}{key: "host=h sslrootcert=/etc/hostname"}), key)
	}
}

// The refusal must come from the key allow-list, before pgx touches a file: a
// path that happens to exist (or not) must make no difference.
func TestParseTenantDSN_FileKeysAreRejectedByTheAllowListNotByTheFileSystem(t *testing.T) {
	for _, dsn := range []string{
		"host=db.example.com password='x'sslrootcert=/etc/hosts",
		"host=db.example.com password='x'sslrootcert=/does/not/exist",
		"host=db.example.com sslkey=/does/not/exist",
		"postgres://u:p@db.example.com/app?sslcert=/does/not/exist",
		"postgres://u:p@db.example.com/app?passfile=/does/not/exist",
		"service=prod",
	} {
		_, err := parseTenantDSN(dsn)
		require.ErrorContains(t, err, "ConnStringAllowedKeys", dsn)
	}
}

func TestParseTenantDSN_PasswordIsDecidedFromTheParsedKeys(t *testing.T) {
	t.Setenv("PGPASSWORD", "opsecret")
	// The old substring check kept the operator's password whenever its text
	// appeared anywhere in the DSN, which made it a guessing oracle.
	conf, err := parseTenantDSN("host=db.example.com user=u application_name=opsecret")
	require.NoError(t, err)
	require.Empty(t, conf.ConnConfig.Password)

	conf, err = parseTenantDSN("host=db.example.com user=u password=opsecret")
	require.NoError(t, err)
	require.Equal(t, "opsecret", conf.ConnConfig.Password, "written by the tenant, so theirs")
}

func TestParseTenantDSN_HostMustBeWrittenInTheDSN(t *testing.T) {
	t.Setenv("PGHOST", "db.internal")
	for _, dsn := range []string{"user=u dbname=app", "postgres:///app?user=u"} {
		_, err := parseTenantDSN(dsn)
		require.ErrorIs(t, err, errTenantDSN, dsn)
	}
	_, err := parseTenantDSN("host=db.example.com user=u")
	require.NoError(t, err)
}

func writeCAFile(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "operator-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	return path
}

// The operator's CA file, named by the pod environment, must not decide whom a
// tenant connection trusts.
func TestParseTenantDSN_OperatorTrustRootsDoNotApply(t *testing.T) {
	t.Setenv("PGSSLROOTCERT", writeCAFile(t))

	conf, err := parseTenantDSN("host=db.example.com user=u sslmode=verify-full")
	require.NoError(t, err)
	require.Nil(t, conf.ConnConfig.TLSConfig.RootCAs, "verification falls back to the system pool")
	require.Empty(t, conf.ConnConfig.TLSConfig.Certificates)
	require.Equal(t, "db.example.com", conf.ConnConfig.TLSConfig.ServerName)

	_, err = parseTenantDSN("host=db.example.com user=u sslmode=verify-ca")
	require.ErrorIs(t, err, errTenantDSN, "verify-ca keeps the original roots in a closure, so it is refused")
}

// On a self-hosted gateway the tenant is the operator: the DSN keeps every pgx
// parameter and only the dial is guarded.
func TestTenantSettings_SelfHostedDSNKeepsAllPgxParameters(t *testing.T) {
	netguardtest.Allow(t)
	tpl := NewTemplate(testLogger(), nil)
	dsn := "host=127.0.0.1 port=1 user=u sslmode=disable options='-c search_path=x' sslrootcert=/does/not/exist"

	require.NoError(t, tpl.ValidateTenantConfig(map[string]interface{}{"dsn": dsn}))
	_, err := tpl.WithTenantSettings(map[string]interface{}{"dsn": dsn})
	require.Error(t, err)
	require.NotErrorIs(t, err, errTenantDSN)
	require.NotContains(t, err.Error(), "ConnStringAllowedKeys")

	// A DSN pgx can parse is built (and fails only at the connect).
	_, err = tpl.WithTenantSettings(map[string]interface{}{"dsn": "host=127.0.0.1 port=1 user=u sslmode=disable options='-c search_path=x'"})
	require.Error(t, err)
	require.NotErrorIs(t, err, errTenantDSN)
	require.NotContains(t, err.Error(), "ConnStringAllowedKeys", "built without the tenant allow-list")
}

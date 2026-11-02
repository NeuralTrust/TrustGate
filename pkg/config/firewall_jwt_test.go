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
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NeuralTrust/TrustGate/pkg/common/errors"
)

const (
	testFirewallClientID     = "client-7f3a"
	testFirewallClientSecret = "secret-value-that-must-never-leak-0123456789" // #nosec G101 -- test fixture
	testFirewallURL          = "https://fw.example"
)

func firewallJWT(t *testing.T, mutate func(jwt.MapClaims), key string, method jwt.SigningMethod) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss":           firewallJWTIssuer,
		"typ":           firewallJWTType,
		"url":           testFirewallURL + "/",
		"client_id":     testFirewallClientID,
		"client_secret": testFirewallClientSecret,
		"iat":           time.Now().Unix(),
	}
	if mutate != nil {
		mutate(claims)
	}
	if key == "" {
		key = testFirewallClientSecret
	}
	if method == nil {
		method = jwt.SigningMethodHS256
	}
	signed, err := jwt.NewWithClaims(method, claims).SignedString([]byte(key))
	require.NoError(t, err)
	return signed
}

func TestFirewallComplexityConfigFromJWT(t *testing.T) {
	valid := firewallJWT(t, nil, "", nil)

	t.Run("valid token gives client and url", func(t *testing.T) {
		t.Setenv(firewallBaseURLEnv, "")
		t.Setenv("FIREWALL_SECRET_KEY", "")
		t.Setenv(firewallJWTEnv, valid)
		cfg := getFirewallComplexityConfig()
		require.NoError(t, cfg.JWTError)
		assert.True(t, cfg.JWTSet)
		assert.Equal(t, testFirewallClientID, cfg.ClientID)
		assert.Equal(t, testFirewallClientSecret, cfg.ClientSecret)
		assert.Equal(t, testFirewallURL, cfg.BaseURL)
		assert.Equal(t, firewallJWTEnv, cfg.BaseURLSource)
	})

	t.Run("quoted value is accepted", func(t *testing.T) {
		t.Setenv(firewallBaseURLEnv, "")
		t.Setenv(firewallJWTEnv, ` "`+valid+`" `)
		cfg := getFirewallComplexityConfig()
		require.NoError(t, cfg.JWTError)
		assert.Equal(t, testFirewallClientID, cfg.ClientID)
	})

	t.Run("explicit base url wins", func(t *testing.T) {
		t.Setenv(firewallBaseURLEnv, "http://firewall.firewall.svc.cluster.local:80")
		t.Setenv(firewallJWTEnv, valid)
		cfg := getFirewallComplexityConfig()
		require.NoError(t, cfg.JWTError)
		assert.Equal(t, "http://firewall.firewall.svc.cluster.local:80", cfg.BaseURL)
		assert.Equal(t, firewallBaseURLEnv, cfg.BaseURLSource)
	})

	t.Run("secret key is kept but the token wins", func(t *testing.T) {
		t.Setenv(firewallBaseURLEnv, "")
		t.Setenv("FIREWALL_SECRET_KEY", "legacy")
		t.Setenv(firewallJWTEnv, valid)
		cfg := getFirewallComplexityConfig()
		require.NoError(t, cfg.JWTError)
		assert.True(t, cfg.JWTSet)
		assert.Equal(t, "legacy", cfg.SecretKey)
	})

	t.Run("legacy only is unchanged", func(t *testing.T) {
		t.Setenv(firewallBaseURLEnv, "http://fw.local")
		t.Setenv("FIREWALL_SECRET_KEY", "legacy")
		t.Setenv(firewallJWTEnv, "")
		cfg := getFirewallComplexityConfig()
		assert.Equal(t, FirewallComplexityConfig{
			BaseURL:       "http://fw.local",
			SecretKey:     "legacy",
			Timeout:       defaultFirewallComplexityTimeout,
			ModelRevision: defaultFirewallComplexityModelRevision,
		}, cfg)
	})
}

func TestFirewallComplexityConfigInvalidJWT(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want string
	}{
		{"malformed", "not-a-jwt", "is malformed"},
		{"wrong algorithm", firewallJWT(t, nil, "", jwt.SigningMethodHS512), "unsupported signing algorithm"},
		{"no secret", firewallJWT(t, func(c jwt.MapClaims) { delete(c, "client_secret") }, "other-key", nil), "missing the client_secret"},
		{"bad signature", firewallJWT(t, nil, "another-secret-entirely-0123456789", nil), "invalid signature"},
		{"expired", firewallJWT(t, func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Minute).Unix() }, "", nil), "has expired"},
		{"wrong issuer", firewallJWT(t, func(c jwt.MapClaims) { c["iss"] = "someone" }, "", nil), "wrong issuer"},
		{"wrong type", firewallJWT(t, func(c jwt.MapClaims) { c["typ"] = "other" }, "", nil), "wrong typ"},
		{"no client id", firewallJWT(t, func(c jwt.MapClaims) { delete(c, "client_id") }, "", nil), "missing the client_id"},
		{"relative url", firewallJWT(t, func(c jwt.MapClaims) { c["url"] = "/fw" }, "", nil), "invalid url"},
		{"non-http url", firewallJWT(t, func(c jwt.MapClaims) { c["url"] = "ftp://fw.example" }, "", nil), "invalid url"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(firewallBaseURLEnv, "")
			t.Setenv("FIREWALL_SECRET_KEY", "legacy")
			t.Setenv(firewallJWTEnv, tc.raw)
			cfg := getFirewallComplexityConfig()
			require.Error(t, cfg.JWTError)
			assert.ErrorIs(t, cfg.JWTError, errors.ErrInvalidConfig)
			assert.Contains(t, cfg.JWTError.Error(), firewallJWTEnv)
			assert.Contains(t, cfg.JWTError.Error(), tc.want)
			assert.True(t, cfg.JWTSet)
			assert.Empty(t, cfg.ClientID)
			assert.Empty(t, cfg.ClientSecret)
			for _, leaked := range []string{tc.raw, testFirewallClientSecret, testFirewallClientID} {
				assert.NotContains(t, cfg.JWTError.Error(), leaked)
			}
		})
	}
}

func TestLoadConfigInvalidFirewallJWTStillLoads(t *testing.T) {
	minimumEnv(t)
	t.Setenv(firewallJWTEnv, "not-a-jwt")
	cfg, err := LoadConfig()
	require.NoError(t, err)
	assert.Error(t, cfg.FirewallComplexity.JWTError)
}

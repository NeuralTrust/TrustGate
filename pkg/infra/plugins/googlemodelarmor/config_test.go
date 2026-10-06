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

package googlemodelarmor

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/common/gcpkey"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/gcpauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validSettings() map[string]any {
	return map[string]any{
		"project":  "proj",
		"location": "us-central1",
		"template": "tmpl",
	}
}

func TestParseConfigDefaults(t *testing.T) {
	t.Parallel()
	cfg, err := parseConfig(validSettings())
	require.NoError(t, err)
	assert.ElementsMatch(t, allFilters, cfg.BlockOn)
	assert.Equal(t, sdpActionBlock, cfg.SDPAction)
}

func TestParseConfigPreservesExplicitBlockOn(t *testing.T) {
	t.Parallel()
	settings := validSettings()
	settings["block_on"] = []string{"sdp", "csam"}
	cfg, err := parseConfig(settings)
	require.NoError(t, err)
	assert.Equal(t, []string{"sdp", "csam"}, cfg.BlockOn)
}

func TestParseConfigValidation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		mutate  func(map[string]any)
		wantErr bool
	}{
		{name: "valid settings"},
		{
			name:    "missing project rejected",
			mutate:  func(s map[string]any) { delete(s, "project") },
			wantErr: true,
		},
		{
			name:    "blank location rejected",
			mutate:  func(s map[string]any) { s["location"] = "  " },
			wantErr: true,
		},
		{
			name:    "missing template rejected",
			mutate:  func(s map[string]any) { delete(s, "template") },
			wantErr: true,
		},
		{
			name:    "unknown block_on filter rejected",
			mutate:  func(s map[string]any) { s["block_on"] = []string{"sdp", "not_a_filter"} },
			wantErr: true,
		},
		{
			name:    "invalid sdp_action rejected",
			mutate:  func(s map[string]any) { s["sdp_action"] = "mask" },
			wantErr: true,
		},
		{
			name:   "explicit anonymize sdp_action accepted",
			mutate: func(s map[string]any) { s["sdp_action"] = "anonymize" },
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			settings := validSettings()
			if tt.mutate != nil {
				tt.mutate(settings)
			}
			_, err := parseConfig(settings)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestSettingsBlockOnSet(t *testing.T) {
	t.Parallel()
	s := Settings{BlockOn: []string{filterSDP, filterCSAM}}
	set := s.blockOnSet()
	assert.True(t, set[filterSDP])
	assert.True(t, set[filterCSAM])
	assert.False(t, set[filterRAI])
}

func TestParseConfigCredentialsDefaultToEmpty(t *testing.T) {
	t.Parallel()
	cfg, err := parseConfig(validSettings())
	require.NoError(t, err)
	assert.Equal(t, Credentials{}, cfg.Credentials,
		"a policy with no credentials block must keep today's ADC-only behaviour untouched")
}

func TestParseConfigCredentialsImpersonation(t *testing.T) {
	t.Parallel()
	settings := validSettings()
	settings["credentials"] = map[string]any{
		"impersonate_service_account": "modelarmor@customer.iam.gserviceaccount.com",
	}
	cfg, err := parseConfig(settings)
	require.NoError(t, err)
	assert.Equal(t, "modelarmor@customer.iam.gserviceaccount.com", cfg.Credentials.ImpersonateServiceAccount)
	assert.Empty(t, cfg.Credentials.ServiceAccountJSON)
}

func TestParseConfigCredentialsServiceAccountJSON(t *testing.T) {
	t.Parallel()
	settings := validSettings()
	settings["credentials"] = map[string]any{
		"service_account_json": `{"type":"service_account"}`,
	}
	cfg, err := parseConfig(settings)
	require.NoError(t, err)
	assert.Equal(t, `{"type":"service_account"}`, cfg.Credentials.ServiceAccountJSON)
	assert.Empty(t, cfg.Credentials.ImpersonateServiceAccount)
}

func TestParseConfigRejectsBothCredentialPaths(t *testing.T) {
	t.Parallel()
	settings := validSettings()
	settings["credentials"] = map[string]any{
		"impersonate_service_account": "modelarmor@customer.iam.gserviceaccount.com",
		"service_account_json":        `{"type":"service_account"}`,
	}
	_, err := parseConfig(settings)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "set only one of")
}

func TestValidateSettingsWriteRejectsHostileServiceAccountJSON(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		json    string
		wantErr string
	}{
		{name: "hostile token_uri", json: `{"type":"service_account","token_uri":"http://169.254.169.254/token"}`, wantErr: "token_uri"},
		{name: "custom universe", json: `{"type":"service_account","universe_domain":"evil.example"}`, wantErr: "universe_domain"},
		{name: "external account", json: `{"type":"external_account"}`, wantErr: "type"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			settings := validSettings()
			settings["credentials"] = map[string]any{"service_account_json": tt.json}
			err := (&Plugin{}).ValidateSettingsWrite(settings, nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "credentials.service_account_json")
			assert.Contains(t, err.Error(), tt.wantErr)
			assert.NotContains(t, err.Error(), "169.254")
			assert.NotContains(t, err.Error(), "evil.example")
		})
	}
}

func TestValidateSettingsWriteAcceptsGoogleTokenURI(t *testing.T) {
	t.Parallel()
	settings := validSettings()
	settings["credentials"] = map[string]any{
		"service_account_json": `{"type":"service_account","token_uri":"https://oauth2.googleapis.com/token"}`,
	}
	require.NoError(t, (&Plugin{}).ValidateSettingsWrite(settings, nil))
}

// A policy stored before the write-time rule must keep loading; the runtime
// pin, not parseConfig, is what keeps its key from redirecting the assertion.
func TestStoredHostileServiceAccountStillParsesAndIsPinned(t *testing.T) {
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rawStored, err := json.Marshal(map[string]string{
		"type":         "service_account",
		"token_uri":    "http://169.254.169.254/token",
		"client_email": "sa@p.iam.gserviceaccount.com",
		"private_key": string(pem.EncodeToMemory(&pem.Block{
			Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key),
		})),
	})
	require.NoError(t, err)
	stored := string(rawStored)
	settings := validSettings()
	settings["credentials"] = map[string]any{"service_account_json": stored}

	cfg, err := parseConfig(settings)
	require.NoError(t, err)
	require.Error(t, (&Plugin{}).ValidateSettingsWrite(settings, nil))

	var seen []string
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		seen = append(seen, r.URL.String())
		return nil, errors.New("blocked in test")
	})}
	_, _ = gcpauth.NewServiceAccountCache(gcpauth.WithHTTPClient(client)).
		Token(context.Background(), cfg.Credentials.ServiceAccountJSON, gcpauth.CloudPlatformScope)
	assert.Equal(t, []string{gcpkey.TokenURL}, seen)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestValidateSettingsWriteRejectsFinalPassOptOut(t *testing.T) {
	t.Parallel()
	p := &Plugin{allowAmbientIdentity: true}
	settings := validSettings()
	settings["streaming"] = map[string]any{"final_pass": false}

	err := p.ValidateSettingsWrite(settings, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "streaming.final_pass")
	require.NoError(t, p.ValidateSettingsWrite(settings, settings),
		"a policy already stored with final_pass: false must stay editable")
	require.NoError(t, p.ValidateConfig(settings), "the rule applies on write only, never when a policy loads")
}

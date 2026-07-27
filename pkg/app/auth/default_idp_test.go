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

package auth_test

import (
	"testing"

	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/stretchr/testify/require"
)

func TestBuildDefaultIdP_DisabledWhenNoIssuer(t *testing.T) {
	require.Nil(t, appauth.BuildDefaultIdP(appauth.DefaultIdPConfig{}))
	require.Nil(t, appauth.BuildDefaultIdP(appauth.DefaultIdPConfig{Issuer: "   "}))
}

func TestBuildDefaultIdP_DerivesEndpointsAndDefaults(t *testing.T) {
	a := appauth.BuildDefaultIdP(appauth.DefaultIdPConfig{
		Issuer:       "https://app.neuraltrust.ai/api/mcp/oauth/",
		ClientID:     "trustgate",
		ClientSecret: "s3cret",
	})
	require.NotNil(t, a)
	require.Equal(t, appauth.DefaultIdPAuthID(), a.ID)
	require.Equal(t, authdomain.TypeOAuth2, a.Type)
	require.True(t, a.Enabled)
	require.True(t, appauth.IsDefaultIdP(a))

	cfg := a.Config.OAuth2
	require.NotNil(t, cfg)
	// Trailing slash trimmed; endpoints derived from the issuer.
	require.Equal(t, "https://app.neuraltrust.ai/api/mcp/oauth", cfg.Issuer)
	require.Equal(t, "https://app.neuraltrust.ai/api/mcp/oauth/authorize", cfg.AuthorizeURL)
	require.Equal(t, "https://app.neuraltrust.ai/api/mcp/oauth/token", cfg.TokenURL)
	require.Equal(t, "https://app.neuraltrust.ai/api/mcp/oauth/jwks", cfg.JWKSURL)
	require.Equal(t, []string{"neuraltrust-mcp"}, cfg.Audiences)
	require.True(t, cfg.SessionMode)
	require.Equal(t, "trustgate", cfg.ClientID)
	require.Equal(t, "s3cret", cfg.ClientSecret)
}

func TestBuildDefaultIdP_HonoursExplicitEndpointsAndAudiences(t *testing.T) {
	a := appauth.BuildDefaultIdP(appauth.DefaultIdPConfig{
		Issuer:       "https://issuer.example",
		AuthorizeURL: "https://a.example/authorize",
		TokenURL:     "https://a.example/token",
		JWKSURL:      "https://a.example/jwks",
		ClientID:     "c",
		Audiences:    []string{"aud-1", "  "},
	})
	require.NotNil(t, a)
	cfg := a.Config.OAuth2
	require.Equal(t, "https://a.example/authorize", cfg.AuthorizeURL)
	require.Equal(t, "https://a.example/token", cfg.TokenURL)
	require.Equal(t, "https://a.example/jwks", cfg.JWKSURL)
	require.Equal(t, []string{"aud-1"}, cfg.Audiences)
}

func TestIsDefaultIdP_FalseForNilAndOthers(t *testing.T) {
	require.False(t, appauth.IsDefaultIdP(nil))
	other, err := authdomain.NewAuth(ids.New[ids.GatewayKind](), "custom", authdomain.TypeAPIKey, true, authdomain.Config{})
	require.NoError(t, err)
	require.False(t, appauth.IsDefaultIdP(other))
}

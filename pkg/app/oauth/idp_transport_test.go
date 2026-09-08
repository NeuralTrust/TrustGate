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

package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	"github.com/stretchr/testify/require"
)

// GitHub reports token-endpoint failures with HTTP 200 and an `error` field in
// a form-encoded body rather than a 4xx status. The transport must surface that
// as an OAuth error instead of returning an empty access_token that later
// resurfaces as a misleading "fetch userinfo: 401".
func TestIDPTokenCall_GitHubStyleErrorWithHTTP200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("error=bad_verification_code&error_description=The+code+passed+is+incorrect"))
	}))
	defer srv.Close()

	tr := &idpTransport{client: srv.Client()}
	_, err := tr.tokenCall(context.Background(), srv.URL, url.Values{"code": {"x"}})

	var oe *OAuthError
	require.ErrorAs(t, err, &oe)
	require.Equal(t, "bad_verification_code", oe.Code)
}

// A 200 response with neither an error nor an access_token is unusable and must
// fail loudly at the transport rather than propagating an empty bearer.
func TestIDPTokenCall_EmptyAccessTokenIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token_type":"bearer"}`))
	}))
	defer srv.Close()

	tr := &idpTransport{client: srv.Client()}
	_, err := tr.tokenCall(context.Background(), srv.URL, url.Values{})

	var oe *OAuthError
	require.ErrorAs(t, err, &oe)
	require.Equal(t, "server_error", oe.Code)
}

// A well-formed GitHub-style (form-encoded) success is returned verbatim.
func TestIDPTokenCall_FormEncodedSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		_, _ = w.Write([]byte("access_token=gho_ok&token_type=bearer&scope=read:user"))
	}))
	defer srv.Close()

	tr := &idpTransport{client: srv.Client()}
	doc, err := tr.tokenCall(context.Background(), srv.URL, url.Values{})

	require.NoError(t, err)
	require.Equal(t, "gho_ok", doc["access_token"])
}

func TestIDPEndpoints_StaticAdvertisedFalse(t *testing.T) {
	t.Parallel()
	tr := &idpTransport{}
	ep, err := tr.endpoints(context.Background(), &authdomain.OAuth2Config{
		Issuer:       "https://accounts.google.com",
		AuthorizeURL: "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL:     "https://oauth2.googleapis.com/token",
	})
	require.NoError(t, err)
	require.False(t, ep.advertised)
	require.Equal(t, "https://accounts.google.com", ep.issuer)
	require.Equal(t, "https://accounts.google.com/o/oauth2/v2/auth", ep.authorize)
	require.Equal(t, "https://oauth2.googleapis.com/token", ep.token)
}

func TestIDPEndpoints_MetadataAdvertisedTrue(t *testing.T) {
	t.Parallel()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/oauth-authorization-server" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 srv.URL,
			"authorization_endpoint": srv.URL + "/authorize",
			"token_endpoint":         srv.URL + "/token",
			"authorization_response_iss_parameter_supported": true,
		})
	}))
	t.Cleanup(srv.Close)

	meta := &metadataService{client: srv.Client(), asCache: map[string]asCacheEntry{}}
	tr := newIDPTransport(srv.Client(), meta)
	ep, err := tr.endpoints(context.Background(), &authdomain.OAuth2Config{Issuer: srv.URL})
	require.NoError(t, err)
	require.True(t, ep.advertised)
	require.Equal(t, srv.URL, ep.issuer)
}

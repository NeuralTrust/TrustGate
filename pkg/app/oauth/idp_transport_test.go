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
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

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

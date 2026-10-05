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

package oauth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	infraoauth "github.com/NeuralTrust/TrustGate/pkg/infra/oauth"
	"github.com/stretchr/testify/require"
)

func TestEnsureClient_RejectionBodyIsNotEchoed(t *testing.T) {
	t.Parallel()
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"x","leak":"INTERNAL-METADATA-CREDENTIAL"}`))
	}))
	defer idp.Close()
	r := infraoauth.NewUpstreamRegistrar(newClaimStore(), idp.Client())
	_, err := r.EnsureClient(context.Background(), "gw|reg",
		&appoauth.UpstreamAuthServer{RegistrationEndpoint: idp.URL}, "https://gw.example.com/cb")
	require.ErrorIs(t, err, appoauth.ErrUpstreamRegistrationRejected)
	require.Contains(t, err.Error(), "status 403")
	require.NotContains(t, err.Error(), "INTERNAL-METADATA-CREDENTIAL")
}

func TestEnsureClient_RejectionKeepsOnlyRegisteredErrorCodes(t *testing.T) {
	t.Parallel()
	for body, want := range map[string]string{
		`{"error":"invalid_redirect_uri","error_description":"secret"}`: "invalid_redirect_uri",
		`{"error":"anything else"}`:                                     "",
	} {
		idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(body))
		}))
		r := infraoauth.NewUpstreamRegistrar(newClaimStore(), idp.Client())
		_, err := r.EnsureClient(context.Background(), "gw|reg",
			&appoauth.UpstreamAuthServer{RegistrationEndpoint: idp.URL}, "https://gw.example.com/cb")
		idp.Close()
		require.Error(t, err)
		require.NotContains(t, err.Error(), "secret")
		if want != "" {
			require.Contains(t, err.Error(), want)
		} else {
			require.NotContains(t, err.Error(), "anything else")
		}
	}
}

func TestProviderClient_TokenErrorDescriptionIsCappedAndStripped(t *testing.T) {
	t.Parallel()
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"a\r\nb\u0000` + strings.Repeat("Z", 4000) + `"}`))
	}))
	defer idp.Close()
	_, err := infraoauth.NewProviderClient(idp.Client()).ExchangeCode(context.Background(),
		&registrydomain.MCPAuth{ClientID: "id", TokenURL: idp.URL}, "c", "https://cb", "v")
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid_client")
	require.Less(t, len(err.Error()), 400)
	require.False(t, strings.ContainsAny(err.Error(), "\r\n\x00"))
}

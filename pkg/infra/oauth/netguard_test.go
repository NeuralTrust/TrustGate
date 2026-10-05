// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
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
	"sync/atomic"
	"testing"

	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/netguard"
	infraoauth "github.com/NeuralTrust/TrustGate/pkg/infra/oauth"
	"github.com/stretchr/testify/require"
)

// hostile stands in for an internal service a tenant points an OAuth URL at.
// httptest listens on loopback, which the guard refuses by default; the tests
// below rely on the flag being off, which is the package default.
func hostile(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{\"access_token\":\"a\",\"sub\":\"s\"}"))
	}))
	t.Cleanup(srv.Close)
	require.False(t, netguard.AllowPrivate(), "guard tests need the escape hatch off")
	return srv, &hits
}

func TestDefaultClients_RefuseInternalDestinations(t *testing.T) {
	ctx := context.Background()

	t.Run("token endpoint", func(t *testing.T) {
		srv, hits := hostile(t)
		_, err := infraoauth.NewProviderClient(nil).ExchangeCode(ctx,
			&registrydomain.MCPAuth{ClientID: "id", ClientSecret: "secret", TokenURL: srv.URL}, "code", "https://cb", "v")
		require.ErrorIs(t, err, netguard.ErrBlockedDestination)
		require.Zero(t, hits.Load())
	})

	t.Run("userinfo", func(t *testing.T) {
		srv, hits := hostile(t)
		_, err := infraoauth.NewUserInfoClient(nil).Fetch(ctx, srv.URL, "tok")
		require.ErrorIs(t, err, netguard.ErrBlockedDestination)
		require.Zero(t, hits.Load())
	})

	t.Run("DCR discovery", func(t *testing.T) {
		srv, hits := hostile(t)
		reg := infraoauth.NewUpstreamRegistrar(newClaimStore(), nil)
		_, err := reg.Discover(ctx, srv.URL+"/mcp")
		require.Error(t, err)
		require.Zero(t, hits.Load())
	})

	t.Run("DCR registration endpoint", func(t *testing.T) {
		srv, hits := hostile(t)
		reg := infraoauth.NewUpstreamRegistrar(newClaimStore(), nil)
		_, err := reg.EnsureClient(ctx, "k", &appoauth.UpstreamAuthServer{RegistrationEndpoint: srv.URL}, "https://cb")
		require.ErrorIs(t, err, netguard.ErrBlockedDestination)
		require.Zero(t, hits.Load())
	})
}

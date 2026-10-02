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
	"net/url"
	"testing"

	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	"github.com/NeuralTrust/TrustGate/pkg/infra/netguard"
	"github.com/NeuralTrust/TrustGate/pkg/infra/netguard/netguardtest"
	"github.com/stretchr/testify/require"
)

// The proxy talks to identity providers whose URLs a tenant configures. With no
// client injected it must default to the guarded one.
func TestAuthProxy_DefaultClientRefusesInternalIdP(t *testing.T) {
	netguardtest.Deny(t)
	p, ok := NewAuthProxy(nil, nil, nil, nil, nil, nil, nil).(*authProxy)
	require.True(t, ok)

	t.Run("token endpoint", func(t *testing.T) {
		srv, hits := netguardtest.Hostile(t, nil)
		_, err := p.idp.tokenCall(context.Background(), srv.URL, url.Values{"client_secret": {"s"}})
		require.ErrorIs(t, err, netguard.ErrBlockedDestination)
		require.Zero(t, hits.Load())
	})

	t.Run("authorization server metadata of an internal issuer", func(t *testing.T) {
		srv, hits := netguardtest.Hostile(t, nil)
		_, err := p.idp.endpoints(context.Background(), &authdomain.OAuth2Config{Issuer: srv.URL})
		require.ErrorIs(t, err, netguard.ErrBlockedDestination)
		require.Zero(t, hits.Load())
	})
}

func TestMetadataService_DefaultClientRefusesInternalIssuer(t *testing.T) {
	netguardtest.Deny(t)
	svc, ok := NewMetadataService(nil, nil, nil, nil).(*metadataService)
	require.True(t, ok)
	srv, hits := netguardtest.Hostile(t, nil)

	_, err := svc.fetchASMetadata(context.Background(), srv.URL)
	require.ErrorIs(t, err, netguard.ErrBlockedDestination)
	require.Zero(t, hits.Load())
}

func TestAuthProxy_TrustedIdPIsReachableAndTenantIdPIsNot(t *testing.T) {
	netguardtest.Deny(t)
	srv, hits := netguardtest.Hostile(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"a","token_type":"Bearer"}`))
	})
	p, ok := NewAuthProxy(nil, nil, nil, nil, nil, nil, nil).(*authProxy)
	require.True(t, ok)
	operator := authdomain.OAuth2Config{TokenURL: srv.URL, Trusted: true}
	tenant := authdomain.OAuth2Config{TokenURL: srv.URL}

	_, err := p.idp.tokenCall(netguard.TrustedIf(context.Background(), operator.Trusted), operator.TokenURL, url.Values{})
	require.NoError(t, err)
	_, err = p.idp.tokenCall(netguard.TrustedIf(context.Background(), tenant.Trusted), tenant.TokenURL, url.Values{})
	require.ErrorIs(t, err, netguard.ErrBlockedDestination)
	require.EqualValues(t, 1, hits.Load())
}

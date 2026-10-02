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

package oidc_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	"github.com/NeuralTrust/TrustGate/pkg/infra/auth/oidc"
	"github.com/NeuralTrust/TrustGate/pkg/infra/netguard/netguardtest"
	"github.com/stretchr/testify/require"
)

func TestOIDC_DefaultClientsRefuseInternalDestinations(t *testing.T) {
	netguardtest.Deny(t)
	ctx := context.Background()

	t.Run("discovery of an internal issuer", func(t *testing.T) {
		srv, hits := netguardtest.Hostile(t, nil)
		_, err := oidc.NewOAuth2TokenValidator(oidc.NewVerifier(), nil).Validate(ctx, "a.b.c",
			&authdomain.OAuth2Config{Issuer: srv.URL, Audiences: []string{"trustgate"}})
		require.Error(t, err)
		require.Zero(t, hits.Load())
	})

	t.Run("configured internal jwks_url", func(t *testing.T) {
		srv, hits := netguardtest.Hostile(t, nil)
		_, err := oidc.NewJWKSCache(nil, time.Minute).Get(ctx, srv.URL+"/jwks")
		require.ErrorIs(t, err, oidc.ErrJWKSFetch)
		require.Zero(t, hits.Load())
	})
}

// A public issuer controls the discovery document, so an internal jwks_uri
// must be refused when the verifier fetches it, not trusted because the
// document came from a legitimate host.
func TestOIDC_DiscoveredInternalJWKSURIIsRefused(t *testing.T) {
	netguardtest.Deny(t)
	stub := newOIDCStub(t)
	internal, internalHits := netguardtest.Hostile(t, nil)

	issuer, issuerHits := netguardtest.Hostile(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, "{\"jwks_uri\":%q}", internal.URL+"/jwks")
	})
	client := netguardtest.ClientTrusting(strings.TrimPrefix(issuer.URL, "http://"))
	v := oidc.NewOAuth2TokenValidator(oidc.NewVerifierWithCache(oidc.NewJWKSCache(client, time.Minute)), client)

	claims := stub.baseClaims()
	claims["iss"] = issuer.URL
	_, err := v.Validate(context.Background(), stub.sign(t, claims),
		&authdomain.OAuth2Config{Issuer: issuer.URL, Audiences: []string{"trustgate"}})
	require.Error(t, err)
	require.EqualValues(t, 1, issuerHits.Load(), "discovery on the legitimate issuer still works")
	require.Zero(t, internalHits.Load(), "the internal jwks_uri must never be dialled")
}

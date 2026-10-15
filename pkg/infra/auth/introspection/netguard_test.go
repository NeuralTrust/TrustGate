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

package introspection_test

import (
	"context"
	"net/http"
	"testing"

	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	"github.com/NeuralTrust/TrustGate/pkg/infra/auth/introspection"
	"github.com/NeuralTrust/TrustGate/pkg/infra/netguard"
	"github.com/NeuralTrust/TrustGate/pkg/infra/netguard/netguardtest"
	"github.com/stretchr/testify/require"
)

// The introspection URL is tenant input and the request carries the caller's
// token and the tenant's client secret, so an internal target must be refused
// before a single byte is sent.
func TestValidator_DefaultClientRefusesInternalIntrospectionURL(t *testing.T) {
	netguardtest.Deny(t)
	srv, hits := netguardtest.Hostile(t, nil)

	_, err := introspection.NewValidator(nil).Validate(context.Background(), "opaque-token",
		&authdomain.OAuth2Config{IntrospectionURL: srv.URL, ClientID: "id", ClientSecret: "secret"})
	require.Error(t, err)
	require.ErrorIs(t, err, netguard.ErrBlockedDestination)
	require.Zero(t, hits.Load())
}

func TestValidator_TrustedConfigReachesPrivateEndpointAndTenantStillDoesNot(t *testing.T) {
	netguardtest.Deny(t)
	srv, hits := netguardtest.Hostile(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"active":true,"sub":"u","iss":"https://idp.example","exp":4102444800}`))
	})
	v := introspection.NewValidator(nil)
	cfg := authdomain.OAuth2Config{IntrospectionURL: srv.URL, Issuer: "https://idp.example"}

	trusted := cfg
	trusted.Trusted = true
	_, err := v.Validate(context.Background(), "tok", &trusted)
	require.NoError(t, err)
	require.EqualValues(t, 1, hits.Load())

	_, err = v.Validate(context.Background(), "tok", &cfg)
	require.ErrorIs(t, err, netguard.ErrBlockedDestination, "the tenant must not reuse the operator's cached result")
	require.EqualValues(t, 1, hits.Load())
}

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

package resolver

import (
	"net/http/httptest"
	"testing"

	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"
)

func apiKeyConsumer(gw *gatewaydomain.Gateway, rawKey, name string) *appconsumer.RoutableConsumer {
	auth := &authdomain.Auth{
		ID: ids.New[ids.AuthKind](), GatewayID: gw.ID, Name: name,
		Type: authdomain.TypeAPIKey, Enabled: true, KeyHash: authdomain.HashAPIKey(rawKey),
	}
	return &appconsumer.RoutableConsumer{
		Consumer: &consumerdomain.Consumer{
			ID: ids.New[ids.ConsumerKind](), GatewayID: gw.ID, Type: consumerdomain.TypeLLM,
			Slug: "llm1234", Active: true, AuthIDs: []ids.AuthID{auth.ID},
		},
		Auths: []*authdomain.Auth{auth},
	}
}

func resolveWithAPIKey(
	t *testing.T,
	gw *gatewaydomain.Gateway,
	rc *appconsumer.RoutableConsumer,
	header, value string,
) (*appauth.AuthContext, error) {
	t.Helper()
	var got *appauth.AuthContext
	var gotErr error
	app := fiber.New()
	app.Post("/*", func(c *fiber.Ctx) error {
		got, gotErr = NewAPIKeyIdentityResolver().Resolve(c, gw, rc)
		return c.SendStatus(fiber.StatusOK)
	})
	req := httptest.NewRequest(fiber.MethodPost, "/llm1234/v1/chat/completions", nil)
	if header != "" {
		req.Header.Set(header, value)
	}
	_, err := app.Test(req)
	require.NoError(t, err)
	return got, gotErr
}

// An API key's name is the only identity it carries, and the telemetry contract
// publishes it as principal.subject with method api_key. Returning no principal
// left principal_subject and principal_method empty all the way into the SIEM
// finding, and dropped TrustGuard's attributes.user with them.
func TestAPIKeyResolveCarriesThePrincipalItsKeyIdentifies(t *testing.T) {
	gw := &gatewaydomain.Gateway{ID: ids.New[ids.GatewayKind](), Slug: "acme"}
	rc := apiKeyConsumer(gw, "ag_live_key", "batch-runner")

	for _, header := range []string{HeaderAPIKey, HeaderAPIKeyCompat} {
		got, err := resolveWithAPIKey(t, gw, rc, header, "ag_live_key")
		require.NoError(t, err, header)
		require.NotNil(t, got, header)
		require.NotNil(t, got.Principal, "%s: no principal means no identity in telemetry", header)
		require.Equal(t, "batch-runner", got.Principal.Subject, header)
		require.Equal(t, identity.MethodAPIKey, got.Principal.Method, header)
		require.Equal(t, "batch-runner", got.Subject, header)
		require.Equal(t, appauth.MethodAPIKey, got.Method, header)
		require.Equal(t, rc.Consumer.ID, got.ConsumerID, header)
	}
}

// An unnamed key still authenticates; it simply has no subject to publish.
func TestAPIKeyResolveWithoutANameYieldsAnEmptySubjectNotAFailure(t *testing.T) {
	gw := &gatewaydomain.Gateway{ID: ids.New[ids.GatewayKind](), Slug: "acme"}
	rc := apiKeyConsumer(gw, "ag_live_key", "")

	got, err := resolveWithAPIKey(t, gw, rc, HeaderAPIKey, "ag_live_key")
	require.NoError(t, err)
	require.NotNil(t, got.Principal)
	require.Empty(t, got.Principal.Subject)
	require.Equal(t, identity.MethodAPIKey, got.Principal.Method)
}

func TestAPIKeyResolveRejectsAWrongOrMissingKeyWithoutAPrincipal(t *testing.T) {
	gw := &gatewaydomain.Gateway{ID: ids.New[ids.GatewayKind](), Slug: "acme"}
	rc := apiKeyConsumer(gw, "ag_live_key", "batch-runner")

	got, err := resolveWithAPIKey(t, gw, rc, HeaderAPIKey, "ag_wrong_key")
	require.ErrorIs(t, err, ErrUnauthenticated)
	require.Nil(t, got)

	got, err = resolveWithAPIKey(t, gw, rc, "", "")
	require.ErrorIs(t, err, ErrUnauthenticated)
	require.Nil(t, got)
}

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

package middleware_test

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	apiresolver "github.com/NeuralTrust/TrustGate/pkg/api/resolver"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"
)

func personalKey(t *testing.T, owner string, groups ...string) *authdomain.Auth {
	t.Helper()
	key, err := authdomain.NewOwnedAPIKeyAuth(ids.New[ids.GatewayKind](), owner, time.Now().UTC().Add(24*time.Hour), time.Now().UTC())
	require.NoError(t, err)
	key.OwnerGroups = groups
	return key
}

// storeChain resolves a request on path the way the MCP plane does, with the
// paths the resolver would give for the Store or for an application consumer.
func storeChain(t *testing.T, key *authdomain.Auth, path string, host *gatewaydomain.Gateway, headers map[string]string) (middleware.Identity, error) {
	t.Helper()
	match := appconsumer.PathMatch{Consumer: consumerdomain.BuildStoreConsumer(ids.GatewayID{})}
	if path != "/store/mcp" {
		match = appconsumer.PathMatch{
			GatewayID: key.GatewayID,
			Consumer:  &consumerdomain.Consumer{ID: ids.New[ids.ConsumerKind](), GatewayID: key.GatewayID, Slug: "acme", Type: consumerdomain.TypeMCP, Active: true},
		}
	}
	resolver := middleware.NewChainIdentityResolver(
		fakeAPIKeyFinder{auth: key}, fakeCredentialFinder{}, fakePathResolver{matches: []appconsumer.PathMatch{match}},
		&fakeTokenValidator{}, &fakeTokenValidator{}, &fakeMTLSValidator{}, nil, nil, nil, false,
	)
	var (
		got    middleware.Identity
		gotErr error
	)
	app := fiber.New()
	app.Post("/*", func(c *fiber.Ctx) error {
		if host != nil {
			c.SetUserContext(appgateway.WithGateway(c.UserContext(), host))
		}
		got, gotErr = resolver.Resolve(c)
		return c.SendStatus(fiber.StatusOK)
	})
	req := httptest.NewRequest(fiber.MethodPost, path, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	_, err := app.Test(req)
	require.NoError(t, err)
	return got, gotErr
}

// The Store is a person's own surface, and a personal key is a person's own
// credential: it reaches the Store as its owner, with the groups the platform
// recorded, whichever header a client can send it in.
func TestChain_PersonalKeyReachesTheStoreAsItsOwner(t *testing.T) {
	key := personalKey(t, "alice", "engineering", "sre")
	host := &gatewaydomain.Gateway{ID: key.GatewayID, Slug: "acme"}

	for _, headers := range []map[string]string{
		{apiresolver.HeaderAPIKey: key.RawKey},
		{fiber.HeaderAuthorization: "Bearer " + key.RawKey},
	} {
		got, err := storeChain(t, key, "/store/mcp", host, headers)

		require.NoError(t, err)
		require.Equal(t, key.GatewayID, got.GatewayID)
		require.Equal(t, key.ID, got.AuthID)
		require.Equal(t, "alice", got.Principal.Subject)
		require.Equal(t, identity.MethodPersonalKey, got.Principal.Method)
		require.Equal(t, []string{"engineering", "sre"}, got.Principal.Groups())
	}
}

// A key with no groups recorded is still its owner, with no group to match.
func TestChain_PersonalKeyWithoutGroups(t *testing.T) {
	key := personalKey(t, "alice")

	got, err := storeChain(t, key, "/store/mcp", nil, map[string]string{apiresolver.HeaderAPIKey: key.RawKey})

	require.NoError(t, err)
	require.Equal(t, "alice", got.Principal.Subject)
	require.Empty(t, got.Principal.Groups())
	require.Empty(t, got.Principal.Email(), "no email recorded, none claimed")
}

// The owner's email rides on the principal as a session's does, so requests
// and traces show the person behind the key and not their user id.
func TestChain_PersonalKeyCarriesItsOwnersEmail(t *testing.T) {
	key := personalKey(t, "83ca2fa4-9660-4be1-a1b2-3c4d5e6f7a8b", "engineering")
	key.OwnerEmail = "alice@acme.test"

	got, err := storeChain(t, key, "/store/mcp", nil, map[string]string{apiresolver.HeaderAPIKey: key.RawKey})

	require.NoError(t, err)
	require.Equal(t, "83ca2fa4-9660-4be1-a1b2-3c4d5e6f7a8b", got.Principal.Subject, "the subject stays the owner's user id")
	require.Equal(t, "alice@acme.test", got.Principal.Email())
	require.Equal(t, []string{"engineering"}, got.Principal.Groups())
}

func TestChain_PersonalKeyIsRefused(t *testing.T) {
	expired := personalKey(t, "alice")
	past := time.Now().UTC().Add(-time.Minute)
	expired.ExpiresAt = &past
	disabled := personalKey(t, "alice")
	disabled.Enabled = false
	reserved := personalKey(t, "app:someone-elses-consumer")
	foreign := personalKey(t, "alice")

	cases := map[string]struct {
		key  *authdomain.Auth
		path string
		host *gatewaydomain.Gateway
	}{
		"on an application's MCP path": {key: personalKey(t, "alice"), path: "/acme/mcp"},
		"expired":                      {key: expired, path: "/store/mcp"},
		"disabled":                     {key: disabled, path: "/store/mcp"},
		"owner in a gateway namespace": {key: reserved, path: "/store/mcp"},
		"on another gateway's host": {
			key: foreign, path: "/store/mcp",
			host: &gatewaydomain.Gateway{ID: ids.New[ids.GatewayKind](), Slug: "other"},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := storeChain(t, tc.key, tc.path, tc.host, map[string]string{apiresolver.HeaderAPIKey: tc.key.RawKey})
			require.ErrorIs(t, err, apiresolver.ErrUnauthenticated)
		})
	}
}

// An application key stays an application's: the Store is not its surface.
func TestChain_ApplicationKeyStaysOffTheStore(t *testing.T) {
	key, err := authdomain.NewAPIKeyAuth(ids.New[ids.GatewayKind](), "partner-key", true, nil)
	require.NoError(t, err)

	_, err = storeChain(t, key, "/store/mcp", nil, map[string]string{apiresolver.HeaderAPIKey: key.RawKey})

	require.ErrorIs(t, err, apiresolver.ErrUnauthenticated)
}

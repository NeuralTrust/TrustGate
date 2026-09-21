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

package consumer_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	consumerhttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/consumer/response"
	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"
)

type stubConsumerFinder struct {
	items []*domain.Consumer
}

func (s *stubConsumerFinder) FindByID(context.Context, ids.GatewayID, ids.ConsumerID) (*domain.Consumer, error) {
	return nil, errors.New("not used")
}

func (s *stubConsumerFinder) List(context.Context, domain.ListFilter) ([]*domain.Consumer, int, error) {
	return s.items, len(s.items), nil
}

// stubUpstreamAccounts answers the pending count from a table and records who
// it was asked about, which is how the tests see the consumers the listing
// skips without reading the vault at all.
type stubUpstreamAccounts struct {
	pending map[ids.ConsumerID]int
	err     error
	asked   []ids.ConsumerID
}

func (s *stubUpstreamAccounts) State(
	context.Context, ids.GatewayID, ids.ConsumerID,
) (*appoauth.ConsumerUpstreamState, error) {
	return nil, errors.New("not used")
}

func (s *stubUpstreamAccounts) PendingUpstreamAuth(
	_ context.Context, _ ids.GatewayID, consumerID ids.ConsumerID,
) (int, error) {
	s.asked = append(s.asked, consumerID)
	if s.err != nil {
		return 0, s.err
	}
	return s.pending[consumerID], nil
}

func (s *stubUpstreamAccounts) Link(
	context.Context, ids.GatewayID, ids.ConsumerID, ids.RegistryID,
) (*appoauth.ConsumerConnectLink, error) {
	return nil, errors.New("not used")
}

func mcpConsumer(gw ids.GatewayID, name string, identity domain.Identity) *domain.Consumer {
	return &domain.Consumer{
		ID: ids.New[ids.ConsumerKind](), GatewayID: gw, Name: name, Slug: name,
		Type: domain.TypeMCP, Active: true, Identity: identity,
	}
}

func listConsumers(
	t *testing.T,
	gw ids.GatewayID,
	finder *stubConsumerFinder,
	upstream appoauth.ConsumerUpstreamAccounts,
) response.ListConsumerResponse {
	return listConsumersWith(t, gw, finder, upstream, "")
}

func listConsumersWith(
	t *testing.T,
	gw ids.GatewayID,
	finder *stubConsumerFinder,
	upstream appoauth.ConsumerUpstreamAccounts,
	query string,
) response.ListConsumerResponse {
	t.Helper()
	app := fiber.New()
	app.Get("/gateways/:gateway_id/consumers", consumerhttp.NewListConsumerHandler(finder, upstream).Handle)
	url := "/gateways/" + gw.String() + "/consumers"
	if query != "" {
		url += "?" + query
	}
	res, err := app.Test(httptest.NewRequest(http.MethodGet, url, nil))
	require.NoError(t, err)
	defer func() { _ = res.Body.Close() }()
	require.Equal(t, http.StatusOK, res.StatusCode)
	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	var out response.ListConsumerResponse
	require.NoError(t, json.Unmarshal(body, &out))
	return out
}

// An application bound to a server it has not signed into is refused on every
// call to it, and the listing is the only place an admin sees that before a
// user does.
func TestListConsumers_ReportsWhatIsStillUnauthorized(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	owes := mcpConsumer(gw, "batch-jobs", domain.Identity{})
	settled := mcpConsumer(gw, "reporting", domain.Identity{})
	upstream := &stubUpstreamAccounts{pending: map[ids.ConsumerID]int{owes.ID: 2}}

	out := listConsumers(t, gw, &stubConsumerFinder{items: []*domain.Consumer{owes, settled}}, upstream)

	require.Len(t, out.Items, 2)
	require.NotNil(t, out.Items[0].PendingUpstreamAuth)
	require.Equal(t, 2, *out.Items[0].PendingUpstreamAuth)
	require.Nil(t, out.Items[1].PendingUpstreamAuth, "an application that owes nothing carries no count")
}

// Only an application that acts as itself holds accounts of its own: an
// application whose users sign in for themselves owes nothing, and asking would
// only be refused.
func TestListConsumers_SkipsConsumersWithoutAccountsOfTheirOwn(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	machine := mcpConsumer(gw, "batch-jobs", domain.Identity{})
	forUsers := mcpConsumer(gw, "assistant", domain.Identity{
		ActsForUsers: true, Source: domain.IdentitySourceApp,
	})
	llm := &domain.Consumer{
		ID: ids.New[ids.ConsumerKind](), GatewayID: gw, Name: "chat", Slug: "chat",
		Type: domain.TypeLLM, Active: true,
	}
	upstream := &stubUpstreamAccounts{pending: map[ids.ConsumerID]int{machine.ID: 1}}

	out := listConsumers(t, gw, &stubConsumerFinder{items: []*domain.Consumer{machine, forUsers, llm}}, upstream)

	require.Len(t, out.Items, 3)
	require.Equal(t, []ids.ConsumerID{machine.ID}, upstream.asked)
	require.NotNil(t, out.Items[0].PendingUpstreamAuth)
	require.Nil(t, out.Items[1].PendingUpstreamAuth)
	require.Nil(t, out.Items[2].PendingUpstreamAuth)
}

// An unreadable vault is not the same as nothing owed: the listing still
// answers, and leaves the count out rather than reporting a reassuring zero.
func TestListConsumers_LeavesTheCountOutWhenItCannotLook(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	machine := mcpConsumer(gw, "batch-jobs", domain.Identity{})

	out := listConsumers(t, gw, &stubConsumerFinder{items: []*domain.Consumer{machine}},
		&stubUpstreamAccounts{err: errors.New("vault unreachable")})

	require.Len(t, out.Items, 1)
	require.Nil(t, out.Items[0].PendingUpstreamAuth)
}

// A plane without the connect service has no accounts to read; the listing must
// still serve.
func TestListConsumers_ServesWithoutTheConnectService(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	out := listConsumers(t, gw,
		&stubConsumerFinder{items: []*domain.Consumer{mcpConsumer(gw, "batch-jobs", domain.Identity{})}}, nil)

	require.Len(t, out.Items, 1)
	require.Nil(t, out.Items[0].PendingUpstreamAuth)
}

// The Store is served without being stored, so it is in no listing that reads
// the table — and a caller building a picker over everything this gateway serves
// has no other way to reach it.
func TestListConsumers_OffersTheStoreWhenAsked(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	agent := mcpConsumer(gw, "support-agent", domain.Identity{})
	finder := &stubConsumerFinder{items: []*domain.Consumer{agent}}

	out := listConsumersWith(t, gw, finder, nil, "include_synthetic=true")

	require.Len(t, out.Items, 2)
	require.Equal(t, domain.StoreSlug, out.Items[0].Slug)
	require.True(t, out.Items[0].Synthetic)
	require.Equal(t, 2, out.Total)
	require.False(t, out.Items[1].Synthetic)
}

// Opt-in, because every caller that manages consumers wants the opposite: there
// is nothing here to edit, delete or give a key to.
func TestListConsumers_LeavesTheStoreOutByDefault(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	finder := &stubConsumerFinder{items: []*domain.Consumer{mcpConsumer(gw, "support-agent", domain.Identity{})}}

	out := listConsumers(t, gw, finder, nil)

	require.Len(t, out.Items, 1)
	require.False(t, out.Items[0].Synthetic)
	require.Equal(t, 1, out.Total)
}

// It belongs to no page of a table it is not in, so it goes on the first only.
func TestListConsumers_KeepsTheStoreOffLaterPages(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	finder := &stubConsumerFinder{items: []*domain.Consumer{mcpConsumer(gw, "support-agent", domain.Identity{})}}

	out := listConsumersWith(t, gw, finder, nil, "include_synthetic=true&page=2")

	require.Len(t, out.Items, 1)
	require.False(t, out.Items[0].Synthetic)
}

// A filter is a filter: the Store is an MCP consumer and no key holds it, so
// asking for LLM consumers or for the holders of a key must not turn it up.
func TestListConsumers_FiltersApplyToTheStoreToo(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	finder := &stubConsumerFinder{}

	llmOnly := listConsumersWith(t, gw, finder, nil, "include_synthetic=true&type=LLM")
	require.Empty(t, llmOnly.Items)

	byKey := listConsumersWith(t, gw, finder, nil,
		"include_synthetic=true&auth_id="+ids.New[ids.AuthKind]().String())
	require.Empty(t, byKey.Items)

	byName := listConsumersWith(t, gw, finder, nil, "include_synthetic=true&search=store")
	require.Len(t, byName.Items, 1)
	require.True(t, byName.Items[0].Synthetic)
}

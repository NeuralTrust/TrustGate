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
) response.ListConsumerResponse {
	return listConsumersWith(t, gw, finder, "")
}

func listConsumersWith(
	t *testing.T,
	gw ids.GatewayID,
	finder *stubConsumerFinder,
	query string,
) response.ListConsumerResponse {
	t.Helper()
	app := fiber.New()
	app.Get("/gateways/:gateway_id/consumers", consumerhttp.NewListConsumerHandler(finder).Handle)
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

// The per-consumer upstream accounts the listing used to count are gone: an
// instance of an MCP server decides whose account it uses, so there is no
// per-consumer number to report.

func TestListConsumers_Serves(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	out := listConsumers(t, gw,
		&stubConsumerFinder{items: []*domain.Consumer{mcpConsumer(gw, "batch-jobs", domain.Identity{})}})

	require.Len(t, out.Items, 1)
	require.Equal(t, "batch-jobs", out.Items[0].Name)
}

// The Store is served without being stored, so it is in no listing that reads
// the table — and a caller building a picker over everything this gateway serves
// has no other way to reach it.
func TestListConsumers_OffersTheStoreWhenAsked(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	agent := mcpConsumer(gw, "support-agent", domain.Identity{})
	finder := &stubConsumerFinder{items: []*domain.Consumer{agent}}

	out := listConsumersWith(t, gw, finder, "include_synthetic=true")

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

	out := listConsumers(t, gw, finder)

	require.Len(t, out.Items, 1)
	require.False(t, out.Items[0].Synthetic)
	require.Equal(t, 1, out.Total)
}

// It belongs to no page of a table it is not in, so it goes on the first only.
func TestListConsumers_KeepsTheStoreOffLaterPages(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	finder := &stubConsumerFinder{items: []*domain.Consumer{mcpConsumer(gw, "support-agent", domain.Identity{})}}

	out := listConsumersWith(t, gw, finder, "include_synthetic=true&page=2")

	require.Len(t, out.Items, 1)
	require.False(t, out.Items[0].Synthetic)
}

// A filter is a filter: the Store is an MCP consumer and no key holds it, so
// asking for LLM consumers or for the holders of a key must not turn it up.
func TestListConsumers_FiltersApplyToTheStoreToo(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	finder := &stubConsumerFinder{}

	llmOnly := listConsumersWith(t, gw, finder, "include_synthetic=true&type=LLM")
	require.Empty(t, llmOnly.Items)

	byKey := listConsumersWith(t, gw, finder, "include_synthetic=true&auth_id="+ids.New[ids.AuthKind]().String())
	require.Empty(t, byKey.Items)

	byName := listConsumersWith(t, gw, finder, "include_synthetic=true&search=store")
	require.Len(t, byName.Items, 1)
	require.True(t, byName.Items[0].Synthetic)
}

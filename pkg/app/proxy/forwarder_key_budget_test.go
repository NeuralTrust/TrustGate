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

package proxy_test

import (
	"cmp"
	"context"
	"net/http"
	"testing"
	"time"

	appproxy "github.com/NeuralTrust/TrustGate/pkg/app/proxy"
	proxymocks "github.com/NeuralTrust/TrustGate/pkg/app/proxy/mocks"
	domainconsumer "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/tokenratelimit"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const pricedDefault = "gpt-4o-mini"

func keyDollarPolicy() *policy.Policy {
	return &policy.Policy{
		ID:      ids.New[ids.PolicyKind](),
		Name:    "key budget",
		Slug:    tokenratelimit.PluginName,
		Enabled: true,
		Global:  true,
		Mode:    policy.ModeEnforce,
		Settings: map[string]any{
			"partition": "key",
			"unit":      "dollars",
			"aggregate": map[string]any{"max": 1, "time_window": "24h"},
		},
	}
}

func priceTheDefault(regs ...*registrydomain.Registry) {
	for _, reg := range regs {
		reg.LLMTarget.Pricing = &registrydomain.Pricing{
			Overrides: map[string]registrydomain.PriceOverride{pricedDefault: {Input: 0.001, Output: 0.001}},
		}
	}
}

func keyBudgetForwarderWith(t *testing.T, invoker appproxy.ProviderInvoker) (appproxy.Forwarder, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return forwarderWithPlugin(t, invoker, tokenratelimit.New(rdb, adapter.NewRegistry(), nil)), mr
}

func keyBudgetForwarder(t *testing.T) (appproxy.Forwarder, *[]string) {
	t.Helper()
	var sent []string
	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().Invoke(mock.Anything, mock.Anything, mock.Anything).
		RunAndReturn(func(_ context.Context, _ *registrydomain.Registry, req *infracontext.RequestContext) (*appproxy.ProviderResponse, error) {
			sent = append(sent, req.DefaultModel)
			return &appproxy.ProviderResponse{StatusCode: http.StatusOK, Body: []byte(`{}`)}, nil
		}).Maybe()
	fwd, _ := keyBudgetForwarderWith(t, invoker)
	return fwd, &sent
}

func keyBudgetBody(model string) []byte {
	if model == "" {
		return []byte(`{"messages":[{"role":"user","content":"hi"}]}`)
	}
	return []byte(`{"model":"` + model + `","messages":[{"role":"user","content":"hi"}]}`)
}

var modelLessIntents = []string{"", "auto", "pool:fast"}

func TestForward_KeyDollarBudgetPricesTheDefaultOfAModelLessIntent(t *testing.T) {
	for _, model := range modelLessIntents {
		t.Run(cmp.Or(model, "no model"), func(t *testing.T) {
			gatewayID := ids.New[ids.GatewayKind]()
			openai := backendFor(gatewayID, "openai")
			priceTheDefault(openai)
			rc := routableConsumerWith(gatewayID, openai)
			rc.Consumer.ModelPolicies = domainconsumer.ModelPolicies{openai.ID: {Default: pricedDefault}}
			rc.Consumer.LBConfig = &domainconsumer.LBConfig{Enabled: true, PoolAlias: "fast",
				Members: []domainconsumer.LBPoolMember{{RegistryID: openai.ID}}}
			rc.Policies = []*policy.Policy{keyDollarPolicy()}
			fwd, sent := keyBudgetForwarder(t)

			res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
				GatewayID: gatewayID, Consumer: rc,
				Request: &infracontext.RequestContext{
					GatewayID: gatewayID.String(), AuthID: ids.New[ids.AuthKind]().String(),
					ProxyCapability: "chat", SourceFormat: "openai", Body: keyBudgetBody(model),
				},
			})
			require.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.StatusCode, string(res.Body))
			assert.Equal(t, []string{pricedDefault}, *sent)
		})
	}
}

func TestForward_KeyDollarBudgetPricesTheDefaultOnTheStorePath(t *testing.T) {
	grant := storeGrant{name: "P", level: levelGroup, priority: 1, pool: "fast",
		regs: []storeRegistry{{provider: "openai", def: pricedDefault, pooled: true}}}
	for _, model := range modelLessIntents {
		t.Run(cmp.Or(model, "no model"), func(t *testing.T) {
			fx := newStoreFixture(grant)
			req := storeRequest(model, "chat", "")
			req.SourceFormat, req.Body = "openai", keyBudgetBody(model)
			req.GatewayID, req.AuthID, req.OwnerID = fx.data.GatewayID.String(), fx.authID.String(), "alice"
			sel, err := fx.choose(newStoreSelector(workedCatalog), req)
			require.NoError(t, err)
			consumer := *sel.Link.Consumer
			consumer.Policies = []*policy.Policy{keyDollarPolicy()}
			priceTheDefault(consumer.Registries...)
			fwd, sent := keyBudgetForwarder(t)

			res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
				GatewayID: fx.data.GatewayID, Consumer: &consumer, Data: fx.data, Request: req,
				Resolved: &sel.ResolvedRouting, RouteSlug: domainconsumer.StoreSlug, Prechecked: true,
			})
			require.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.StatusCode, string(res.Body))
			assert.Equal(t, []string{pricedDefault}, *sent)
		})
	}
}

func TestForward_KeyDollarBudgetStillRefusesAnUnpricedDefault(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	openai := backendFor(gatewayID, "openai")
	priceTheDefault(openai)
	rc := routableConsumerWith(gatewayID, openai)
	rc.Consumer.ModelPolicies = domainconsumer.ModelPolicies{openai.ID: {Default: "gpt-unpriced"}}
	rc.Policies = []*policy.Policy{keyDollarPolicy()}
	fwd, sent := keyBudgetForwarder(t)

	res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID, Consumer: rc,
		Request: &infracontext.RequestContext{
			GatewayID: gatewayID.String(), AuthID: ids.New[ids.AuthKind]().String(),
			ProxyCapability: "chat", SourceFormat: "openai", Body: keyBudgetBody("auto"),
		},
	})
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, res.StatusCode)
	assert.Contains(t, string(res.Body), "gpt-unpriced")
	assert.Empty(t, *sent)
}

func TestForward_KeyDollarBudgetChargesAModelLessStream(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	openai := backendFor(gatewayID, "openai")
	priceTheDefault(openai)
	rc := routableConsumerWith(gatewayID, openai)
	rc.Consumer.ModelPolicies = domainconsumer.ModelPolicies{openai.ID: {Default: pricedDefault}}
	budget := keyDollarPolicy()
	rc.Policies = []*policy.Policy{budget}
	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().InvokeStream(mock.Anything, mock.Anything, mock.Anything).
		RunAndReturn(func(_ context.Context, _ *registrydomain.Registry, req *infracontext.RequestContext) (*appproxy.ProviderResponse, error) {
			req.Metadata = map[string]any{adapter.MetadataUsageKey: &adapter.CanonicalUsage{InputTokens: 10, TotalTokens: 10}}
			return &appproxy.ProviderResponse{StatusCode: http.StatusOK, Stream: func(yield func([]byte, error) bool) {
				yield([]byte("data: [DONE]"), nil)
			}}, nil
		}).Once()
	fwd, mr := keyBudgetForwarderWith(t, invoker)
	authID := ids.New[ids.AuthKind]().String()

	res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID, Consumer: rc,
		Request: &infracontext.RequestContext{
			GatewayID: gatewayID.String(), AuthID: authID, ProxyCapability: "chat", SourceFormat: "openai",
			Body: []byte(`{"messages":[{"role":"user","content":"hi"}],"stream":true}`),
		},
	})
	require.NoError(t, err)
	require.NotNil(t, res.Stream)
	for _, err := range res.Stream {
		require.NoError(t, err)
	}
	counter := "trl:" + budget.ID.String() + ":key:auth:" + authID
	assert.Eventually(t, func() bool {
		spent, err := mr.Get(counter)
		return err == nil && spent == "10000"
	}, 2*time.Second, 10*time.Millisecond)
}

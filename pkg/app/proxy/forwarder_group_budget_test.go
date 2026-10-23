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
	"context"
	"net/http"
	"testing"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	appproxy "github.com/NeuralTrust/TrustGate/pkg/app/proxy"
	proxymocks "github.com/NeuralTrust/TrustGate/pkg/app/proxy/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	keygroupdomain "github.com/NeuralTrust/TrustGate/pkg/domain/keygroup"
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

// groupBudgetForwarder is a forwarder whose gateway registry holds only the
// token_rate_limiter: the group budget reaches it through WithGroupBudget.
func groupBudgetForwarder(t *testing.T, invoked *int) (appproxy.Forwarder, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().Invoke(mock.Anything, mock.Anything, mock.Anything).
		RunAndReturn(func(context.Context, *registrydomain.Registry, *infracontext.RequestContext) (*appproxy.ProviderResponse, error) {
			*invoked++
			return &appproxy.ProviderResponse{StatusCode: http.StatusOK, Body: []byte(`{"id":"x","model":"` + pricedDefault +
				`","choices":[{"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],` +
				`"usage":{"prompt_tokens":300,"completion_tokens":300,"total_tokens":600}}`)}, nil
		}).Maybe()
	stage := tokenratelimit.NewGroupBudget(rdb, adapter.NewRegistry(), nil, nil, newTestLogger())
	return forwarderWithPlugin(t, invoker, tokenratelimit.New(rdb, adapter.NewRegistry(), nil), appproxy.WithGroupBudget(stage)), mr
}

func groupKeyRequest(gatewayID ids.GatewayID, budget *keygroupdomain.Budget) *infracontext.RequestContext {
	return &infracontext.RequestContext{
		GatewayID: gatewayID.String(), AuthID: ids.New[ids.AuthKind]().String(), OwnerID: "alice",
		KeyGroupID: "g-eng", KeyGroupBudget: budget,
		ProxyCapability: "chat", SourceFormat: "openai", Body: keyBudgetBody(pricedDefault),
	}
}

// plannedConsumer is a personal consumer as the gateway's data loads it: its
// plan is compiled, here from no policies.
func plannedConsumer(gatewayID ids.GatewayID) *appconsumer.RoutableConsumer {
	openai := backendFor(gatewayID, "openai")
	priceTheDefault(openai)
	rc := routableConsumerWith(gatewayID, openai)
	rc.PolicyPlan = appplugins.NewInertStagePlan(appplugins.NewRegistry(), nil, newTestLogger())
	return rc
}

func TestForward_GroupKeyIsHeldToItsGroupsBudget(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	rc := plannedConsumer(gatewayID)
	invoked := 0
	fwd, mr := groupBudgetForwarder(t, &invoked)
	budget, err := keygroupdomain.NewBudget(gatewayID, "g-eng", ptrUSD(1), nil, nil, keygroupdomain.ActionBlock, time.Now())
	require.NoError(t, err)
	counter := "kgb:" + gatewayID.String() + ":g-eng:p:" + time.Now().UTC().Format("2006-01")

	for i, spent := range []string{"600000", "1200000"} {
		res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{GatewayID: gatewayID, Consumer: rc, Request: groupKeyRequest(gatewayID, budget)})
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, res.StatusCode, "request %d: %s", i, res.Body)
		assert.Eventually(t, func() bool {
			got, err := mr.Get(counter)
			return err == nil && got == spent
		}, 2*time.Second, 10*time.Millisecond, "every answer is charged to its group")
	}

	res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{GatewayID: gatewayID, Consumer: rc, Request: groupKeyRequest(gatewayID, budget)})
	require.NoError(t, err)
	assert.Equal(t, http.StatusTooManyRequests, res.StatusCode)
	assert.Contains(t, string(res.Body), `"type":"budget_exceeded"`)
	assert.Equal(t, 2, invoked, "a spent group's request never reaches the provider")
	assert.Empty(t, rc.Policies, "the consumer's own policies are left as they were")
}

func TestForward_KeyWithoutAGroupBudgetIsNotCounted(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	rc := plannedConsumer(gatewayID)
	invoked := 0
	fwd, mr := groupBudgetForwarder(t, &invoked)

	res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{GatewayID: gatewayID, Consumer: rc, Request: groupKeyRequest(gatewayID, nil)})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, res.StatusCode)
	assert.Equal(t, 1, invoked)
	assert.Empty(t, mr.Keys(), "nothing runs after the answer: the consumer has no policy and the key no budget")
}

func ptrUSD(v float64) *float64 { return &v }

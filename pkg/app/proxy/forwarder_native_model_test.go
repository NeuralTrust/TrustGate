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
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"testing"
	"time"

	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	catalogmocks "github.com/NeuralTrust/TrustGate/pkg/app/catalog/mocks"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	appproxy "github.com/NeuralTrust/TrustGate/pkg/app/proxy"
	proxymocks "github.com/NeuralTrust/TrustGate/pkg/app/proxy/mocks"
	approuting "github.com/NeuralTrust/TrustGate/pkg/app/routing"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/loadbalancer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const (
	opaqueARN   = "arn:aws:bedrock:us-east-1:123456789012:application-inference-profile/abc123xyz"
	opaqueModel = "anthropic.claude-sonnet-4-5-20250929-v1:0"
	opaqueFound = "arn:aws:bedrock:us-east-1::foundation-model/" + opaqueModel
)

func awsBedrockRegistry(gatewayID ids.GatewayID) *registrydomain.Registry {
	reg := backendFor(gatewayID, "bedrock")
	reg.LLMTarget.Auth = &registrydomain.TargetAuth{
		Type: registrydomain.AuthTypeAWS,
		AWS:  &registrydomain.AWSAuth{Region: "us-east-1", AccessKeyID: "AKIA", SecretAccessKey: "secret"},
	}
	return reg
}

// resolverForwarder wires a forwarder with a pre_request plugin that records the
// model the cost cap and the budgets would see.
func resolverForwarder(
	t *testing.T,
	invoker appproxy.ProviderInvoker,
	models appcatalog.BedrockModelResolver,
	seen chan string,
) appproxy.Forwarder {
	t.Helper()
	reg := appplugins.NewRegistry()
	require.NoError(t, reg.Register(&recordingPlugin{seen: seen}))
	exec := appplugins.NewExecutor(reg, newTestLogger())
	return appproxy.NewForwarder(
		loadbalancer.NewBaseFactory(nil, nil, nil, nil, nil),
		newPermissiveCache(t), cache.NewTTLMapManager(time.Minute), invoker, exec, nil, approuting.NewResolver(), nil, nil, nil, newTestLogger(),
		appproxy.WithForwarderBedrockModelResolver(models),
	)
}

type recordingPlugin struct {
	seen chan string
}

func (p *recordingPlugin) Name() string { return "cost_cap_probe" }
func (p *recordingPlugin) MandatoryStages() []policy.Stage {
	return []policy.Stage{policy.StagePreRequest}
}
func (p *recordingPlugin) SupportedStages() []policy.Stage {
	return []policy.Stage{policy.StagePreRequest}
}
func (p *recordingPlugin) SupportedModes() []policy.Mode { return []policy.Mode{policy.ModeEnforce} }
func (p *recordingPlugin) SupportedProtocols() []appplugins.Protocol {
	return []appplugins.Protocol{appplugins.ProtocolLLM}
}
func (p *recordingPlugin) ValidateConfig(map[string]any) error { return nil }
func (p *recordingPlugin) MutatesRequestBody() bool            { return false }
func (p *recordingPlugin) MutatesResponseBody() bool           { return false }
func (p *recordingPlugin) MutatesMetadata() bool               { return false }
func (p *recordingPlugin) Execute(_ context.Context, in appplugins.ExecInput) (*appplugins.Result, error) {
	p.seen <- in.Request.ResolvedModel
	return &appplugins.Result{StatusCode: http.StatusOK}, nil
}

func opaqueConsumer(gatewayID ids.GatewayID, reg *registrydomain.Registry) *appconsumer.RoutableConsumer {
	rc := routableConsumerWith(gatewayID, reg)
	rc.Policies = []*policy.Policy{{ID: ids.New[ids.PolicyKind](), Name: "p", Slug: "cost_cap_probe", Enabled: true, Priority: 1}}
	return rc
}

func okInvoker(t *testing.T) appproxy.ProviderInvoker {
	t.Helper()
	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().Invoke(mock.Anything, mock.Anything, mock.Anything).Return(nativeOKResponse(), nil).Maybe()
	return invoker
}

func forwardOpaque(t *testing.T, fwd appproxy.Forwarder, gatewayID ids.GatewayID, rc *appconsumer.RoutableConsumer, modelID string) error {
	t.Helper()
	_, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID, Consumer: rc, Request: nativeForwardRequest("converse", modelID, `{"messages":[]}`),
	})
	return err
}

func TestForward_NativeOpaqueARN_ColdCacheIsResolvedBeforePreRequest(t *testing.T) {
	cp := catalogmocks.NewBedrockModelARNLookup(t)
	cp.EXPECT().ResolveModelARN(mock.Anything, mock.Anything, opaqueARN).Return(opaqueFound, nil).Once()
	models := appcatalog.NewBedrockModelResolver(cp, slog.New(slog.DiscardHandler))
	gatewayID := ids.New[ids.GatewayKind]()
	seen := make(chan string, 4)
	fwd := resolverForwarder(t, okInvoker(t), models, seen)

	require.NoError(t, forwardOpaque(t, fwd, gatewayID, opaqueConsumer(gatewayID, awsBedrockRegistry(gatewayID)), opaqueARN))
	assert.Equal(t, opaqueModel, <-seen, "the cost cap prices the first call, on a cold cache")
}

func TestForward_NativeOpaqueARN_ConcurrentFirstCallsShareOneLookup(t *testing.T) {
	cp := catalogmocks.NewBedrockModelARNLookup(t)
	cp.EXPECT().ResolveModelARN(mock.Anything, mock.Anything, opaqueARN).
		Run(func(context.Context, appcatalog.BedrockCredentials, string) { time.Sleep(150 * time.Millisecond) }).
		Return(opaqueFound, nil).Once()
	models := appcatalog.NewBedrockModelResolver(cp, slog.New(slog.DiscardHandler))
	gatewayID := ids.New[ids.GatewayKind]()
	reg := awsBedrockRegistry(gatewayID)
	seen := make(chan string, 16)
	fwd := resolverForwarder(t, okInvoker(t), models, seen)

	var wg sync.WaitGroup
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			assert.NoError(t, forwardOpaque(t, fwd, gatewayID, opaqueConsumer(gatewayID, reg), opaqueARN))
		}()
	}
	wg.Wait()
	close(seen)
	for got := range seen {
		assert.Equal(t, opaqueModel, got)
	}
}

func TestForward_NativeOpaqueARN_SlowControlPlaneProceedsUnresolvedAfterTheBound(t *testing.T) {
	cp := catalogmocks.NewBedrockModelARNLookup(t)
	cp.EXPECT().ResolveModelARN(mock.Anything, mock.Anything, opaqueARN).
		Run(func(context.Context, appcatalog.BedrockCredentials, string) { time.Sleep(1800 * time.Millisecond) }).
		Return(opaqueFound, nil).Maybe()
	t.Cleanup(func() { time.Sleep(400 * time.Millisecond) }) // let the background call end
	models := appcatalog.NewBedrockModelResolver(cp, slog.New(slog.DiscardHandler))
	gatewayID := ids.New[ids.GatewayKind]()
	seen := make(chan string, 4)
	fwd := resolverForwarder(t, okInvoker(t), models, seen)

	started := time.Now()
	require.NoError(t, forwardOpaque(t, fwd, gatewayID, opaqueConsumer(gatewayID, awsBedrockRegistry(gatewayID)), opaqueARN),
		"the lookup never fails the request")
	elapsed := time.Since(started)
	assert.Empty(t, <-seen, "unresolved: the cost cap sees an unknown model, as before")
	assert.GreaterOrEqual(t, elapsed, 1400*time.Millisecond, "it waited for the bound")
	assert.Less(t, elapsed, 1750*time.Millisecond, "and not longer")
}

func TestForward_NativeOpaqueARN_FailureAndNegativeEntryNeverWait(t *testing.T) {
	cp := catalogmocks.NewBedrockModelARNLookup(t)
	cp.EXPECT().ResolveModelARN(mock.Anything, mock.Anything, opaqueARN).Return("", errors.New("AccessDeniedException")).Once()
	models := appcatalog.NewBedrockModelResolver(cp, slog.New(slog.DiscardHandler))
	gatewayID := ids.New[ids.GatewayKind]()
	reg := awsBedrockRegistry(gatewayID)
	seen := make(chan string, 4)
	fwd := resolverForwarder(t, okInvoker(t), models, seen)

	require.NoError(t, forwardOpaque(t, fwd, gatewayID, opaqueConsumer(gatewayID, reg), opaqueARN), "a failed lookup never fails the request")
	assert.Empty(t, <-seen)

	started := time.Now()
	require.NoError(t, forwardOpaque(t, fwd, gatewayID, opaqueConsumer(gatewayID, reg), opaqueARN))
	assert.Less(t, time.Since(started), 300*time.Millisecond, "a negative entry does not wait")
	assert.Empty(t, <-seen)
}

// Only opaque ARNs on native routes reach the resolver.
func TestForward_ResolverIsNeverCalledForAnythingElse(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	reg := awsBedrockRegistry(gatewayID)
	cases := map[string]string{
		"plain model id":     "amazon.nova-lite-v1:0",
		"system profile ARN": "arn:aws:bedrock:us-east-1:123456789012:inference-profile/us.anthropic.claude-sonnet-4-5-20250929-v1:0",
		"foundation ARN":     opaqueFound,
		"imported model ARN": "arn:aws:bedrock:us-east-1:123456789012:imported-model/im1",
		"malformed ARN":      "arn:aws:bedrock:nope",
	}
	for name, id := range cases {
		t.Run(name, func(t *testing.T) {
			calls := 0
			models := &stubModels{resolve: func(context.Context, string, time.Duration) (string, bool) { calls++; return "", false }}
			fwd := resolverForwarder(t, okInvoker(t), models, make(chan string, 4))
			require.NoError(t, forwardOpaque(t, fwd, gatewayID, opaqueConsumer(gatewayID, reg), id))
			assert.Zero(t, calls)
		})
	}

	t.Run("a request that is not native", func(t *testing.T) {
		calls := 0
		models := &stubModels{resolve: func(context.Context, string, time.Duration) (string, bool) { calls++; return "", false }}
		fwd := resolverForwarder(t, okInvoker(t), models, make(chan string, 4))
		rc := opaqueConsumer(gatewayID, reg)
		_, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
			GatewayID: gatewayID, Consumer: rc,
			Request: &infracontext.RequestContext{Body: []byte(`{"model":"` + opaqueARN + `"}`)},
		})
		require.NoError(t, err)
		assert.Zero(t, calls)
	})
}

func TestForward_NativeOpaqueARN_ForwarderHandsTheBoundToTheResolver(t *testing.T) {
	var got time.Duration
	models := &stubModels{resolve: func(_ context.Context, _ string, wait time.Duration) (string, bool) {
		got = wait
		return opaqueModel, true
	}}
	gatewayID := ids.New[ids.GatewayKind]()
	fwd := resolverForwarder(t, okInvoker(t), models, make(chan string, 4))
	require.NoError(t, forwardOpaque(t, fwd, gatewayID, opaqueConsumer(gatewayID, awsBedrockRegistry(gatewayID)), opaqueARN))
	assert.Equal(t, 1500*time.Millisecond, got)
}

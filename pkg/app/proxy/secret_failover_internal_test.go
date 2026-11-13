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

package proxy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	approuting "github.com/NeuralTrust/TrustGate/pkg/app/routing"
	domainconsumer "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	cachemocks "github.com/NeuralTrust/TrustGate/pkg/infra/cache/mocks"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/loadbalancer"
)

// literalOnly answers for the literal registry with the credential it
// carries and hands every other registry to the real invoker, which refuses
// a registry whose reference did not resolve before any upstream call.
type literalOnly struct {
	real    ProviderInvoker
	literal ids.RegistryID
	served  []string
}

func (l *literalOnly) Invoke(ctx context.Context, bk *registrydomain.Registry, req *infracontext.RequestContext) (*ProviderResponse, error) {
	if bk.ID != l.literal {
		return l.real.Invoke(ctx, bk, req)
	}
	l.served = append(l.served, bk.LLMTarget.Auth.APIKey.APIKey)
	return &ProviderResponse{StatusCode: 200, Body: []byte("ok")}, nil
}

func (l *literalOnly) InvokeStream(ctx context.Context, bk *registrydomain.Registry, req *infracontext.RequestContext) (*ProviderResponse, error) {
	return l.Invoke(ctx, bk, req)
}

func TestForwardFailsOverFromAnUnresolvedReference(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	primary := &registrydomain.Registry{
		ID: ids.New[ids.RegistryKind](), GatewayID: gw, Name: "vaulted", Type: registrydomain.TypeLLM,
		LLMTarget: &registrydomain.LLMTarget{Provider: "openai", Auth: registrydomain.NewAPIKeyAuth("")},
	}
	primary.MarkCredentialUnavailable()
	literal := &registrydomain.Registry{
		ID: ids.New[ids.RegistryKind](), GatewayID: gw, Name: "literal", Type: registrydomain.TypeLLM,
		LLMTarget: &registrydomain.LLMTarget{Provider: "openai", Auth: registrydomain.NewAPIKeyAuth("sk-literal")},
	}
	rc := &appconsumer.RoutableConsumer{
		Consumer: &domainconsumer.Consumer{
			ID: ids.New[ids.ConsumerKind](), GatewayID: gw, Name: "c", Slug: "c1234567",
			LBConfig: &domainconsumer.LBConfig{Algorithm: loadbalancer.AlgorithmRoundRobin},
			Fallback: &domainconsumer.Fallback{
				Enabled:  true,
				Triggers: []domainconsumer.FallbackTrigger{domainconsumer.TriggerHTTP5xx},
				Budget:   domainconsumer.FallbackBudget{MaxAttempts: 3},
				Chain:    []ids.RegistryID{literal.ID},
			},
		},
		Registries:       []*registrydomain.Registry{primary},
		FallbackBackends: []*registrydomain.Registry{literal},
	}
	redis := cachemocks.NewClient(t)
	redis.EXPECT().Set(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()
	redis.EXPECT().Get(mock.Anything, mock.Anything).Return("", errors.New("miss")).Maybe()
	redis.EXPECT().RedisClient().Return(nil).Maybe()
	invoker := &literalOnly{real: &providerInvoker{}, literal: literal.ID}
	fwd := NewForwarder(loadbalancer.NewBaseFactory(nil, nil, nil, nil, nil), redis, cache.NewTTLMapManager(time.Minute),
		invoker, nil, nil, approuting.NewResolver(), nil, nil, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))

	res, err := fwd.Forward(context.Background(), ForwardInput{GatewayID: gw, Consumer: rc, Request: &infracontext.RequestContext{}})
	if err != nil {
		t.Fatalf("Forward: %v", err)
	}
	if res.StatusCode != 200 {
		t.Fatalf("status = %d, want the request served by the literal registry", res.StatusCode)
	}
	if len(invoker.served) != 1 || invoker.served[0] != "sk-literal" {
		t.Fatalf("upstream calls = %v, want one, with the literal registry's own credential", invoker.served)
	}
}

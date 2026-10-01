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
	"encoding/json"
	"errors"
	"iter"
	"testing"

	appproxy "github.com/NeuralTrust/TrustGate/pkg/app/proxy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	factorymocks "github.com/NeuralTrust/TrustGate/pkg/infra/providers/factory/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errUpstreamReached = errors.New("upstream reached")

type upstreamRecorder struct {
	cfg  *providers.Config
	body []byte
}

func (r *upstreamRecorder) record(cfg *providers.Config, body []byte) error {
	r.cfg, r.body = cfg, body
	return errUpstreamReached
}

func (r *upstreamRecorder) Completions(_ context.Context, cfg *providers.Config, body []byte) ([]byte, error) {
	return nil, r.record(cfg, body)
}

func (r *upstreamRecorder) CompletionsStream(_ context.Context, cfg *providers.Config, body []byte) (iter.Seq2[[]byte, error], error) {
	return nil, r.record(cfg, body)
}

func (r *upstreamRecorder) Embeddings(_ context.Context, cfg *providers.Config, body []byte) ([]byte, error) {
	return nil, r.record(cfg, body)
}

func requestBody(t *testing.T, model string, fields map[string]any) []byte {
	t.Helper()
	body := map[string]any{}
	for k, v := range fields {
		body[k] = v
	}
	if model != "" {
		body["model"] = model
	}
	out, err := json.Marshal(body)
	require.NoError(t, err)
	return out
}

// ENG-1706 / ENG-1705: the binding default fills in a missing model only; a
// model the client sent survives targets whose wire format carries it out of band.
func TestProviderInvoke_RequestedModelSurvivesOutOfBandTargets(t *testing.T) {
	t.Parallel()

	const (
		requested  = "eu.anthropic.claude-opus-5"
		defaultM   = "eu.anthropic.claude-sonnet-4-5"
		disallowed = "gpt-4o"
	)
	chatOpenAI := map[string]any{"messages": []map[string]any{{"role": "user", "content": "hi"}}, "max_tokens": 16}
	chatAnthropic := map[string]any{"max_tokens": 16, "messages": []map[string]any{{"role": "user", "content": "hi"}}}
	embeddings := map[string]any{"input": "hi"}

	targets := []struct {
		name       string
		provider   string
		source     string
		capability string
		stream     bool
		fields     map[string]any
		wantTarget string
	}{
		{name: "bedrock converse from openai", provider: "bedrock", source: "openai", fields: chatOpenAI, wantTarget: "bedrock"},
		{name: "bedrock converse from openai stream", provider: "bedrock", source: "openai", stream: true, fields: chatOpenAI, wantTarget: "bedrock"},
		{name: "bedrock converse from anthropic", provider: "bedrock", source: "anthropic", fields: chatAnthropic, wantTarget: "bedrock"},
		{name: "bedrock converse from anthropic stream", provider: "bedrock", source: "anthropic", stream: true, fields: chatAnthropic, wantTarget: "bedrock"},
		{name: "bedrock titan embeddings", provider: "bedrock", source: string(adapter.FormatOpenAIEmbeddings), capability: "embeddings", fields: embeddings, wantTarget: "bedrock_titan_embed"},
		{name: "vertex embeddings", provider: "vertex", source: string(adapter.FormatOpenAIEmbeddings), capability: "embeddings", fields: embeddings, wantTarget: "vertex_embed"},
		{name: "anthropic from openai", provider: "anthropic", source: "openai", fields: chatOpenAI, wantTarget: "anthropic"},
	}

	scenarios := []struct {
		name      string
		model     string
		allowed   []string
		defaultM  string
		wantModel string
		wantErr   error
	}{
		{name: "wildcard allow-list with default keeps the requested model", model: requested, allowed: []string{"*claude-*"}, defaultM: defaultM, wantModel: requested},
		{name: "concrete allow-list with default keeps the requested model", model: requested, allowed: []string{defaultM, requested}, defaultM: defaultM, wantModel: requested},
		{name: "wildcard allow-list without default keeps the requested model", model: requested, allowed: []string{"eu.anthropic.claude-*"}, wantModel: requested},
		{name: "request without model uses the default", allowed: []string{"*claude-*"}, defaultM: defaultM, wantModel: defaultM},
		{name: "model outside the allow-list is rejected", model: disallowed, allowed: []string{"*claude-*"}, defaultM: defaultM, wantErr: appproxy.ErrModelNotAllowed},
		{name: "request without model and without default is rejected", allowed: []string{"*claude-*"}, wantErr: appproxy.ErrModelNotAllowed},
	}

	for _, tg := range targets {
		for _, sc := range scenarios {
			t.Run(tg.name+"/"+sc.name, func(t *testing.T) {
				t.Parallel()

				upstream := &upstreamRecorder{}
				locator := factorymocks.NewProviderLocator(t)
				locator.EXPECT().Get(tg.provider).Return(upstream, nil).Once()
				inv := appproxy.NewProviderInvoker(locator, adapter.NewRegistry(), newTestLogger())

				req := &infracontext.RequestContext{
					Body:            requestBody(t, sc.model, tg.fields),
					SourceFormat:    tg.source,
					ProxyCapability: tg.capability,
					AllowedModels:   sc.allowed,
					DefaultModel:    sc.defaultM,
				}
				var err error
				if tg.stream {
					_, err = inv.InvokeStream(context.Background(), apiKeyTarget(tg.provider), req)
				} else {
					_, err = inv.Invoke(context.Background(), apiKeyTarget(tg.provider), req)
				}

				assert.Equal(t, tg.wantTarget, req.TargetFormat)
				if sc.wantErr != nil {
					require.ErrorIs(t, err, sc.wantErr)
					assert.Nil(t, upstream.cfg, "a rejected request must not reach the provider")
					return
				}
				require.ErrorIs(t, err, errUpstreamReached)
				require.NotNil(t, upstream.cfg)
				assert.Equal(t, sc.wantModel, upstream.cfg.Model)
				bodyModel, err := adapter.ExtractModel(upstream.body)
				require.NoError(t, err)
				assert.Equal(t, sc.wantModel, bodyModel)
			})
		}
	}
}

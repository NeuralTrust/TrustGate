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

package semanticcache

import (
	"context"
	"errors"
	"net/url"
	"sync"
	"testing"
	"time"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/embedding"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/semantic"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	embeddingfactory "github.com/NeuralTrust/TrustGate/pkg/infra/embedding/factory"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeStore struct {
	candidates  []semantic.Candidate
	lookupErr   error
	stored      []semantic.Entry
	storeErr    error
	ensureErr   error
	exact       map[string]string
	exactPutErr error
}

func (f *fakeStore) EnsureIndex(context.Context, int) error { return f.ensureErr }
func (f *fakeStore) Lookup(context.Context, string, *embedding.Embedding, int) ([]semantic.Candidate, error) {
	return f.candidates, f.lookupErr
}
func (f *fakeStore) Store(_ context.Context, e semantic.Entry) error {
	if f.storeErr != nil {
		return f.storeErr
	}
	f.stored = append(f.stored, e)
	return nil
}
func (f *fakeStore) GetExact(_ context.Context, ruleID, key string) (string, bool, error) {
	if f.exact == nil {
		return "", false, nil
	}
	v, ok := f.exact[ruleID+"|"+key]
	return v, ok, nil
}
func (f *fakeStore) PutExact(_ context.Context, ruleID, key, response string, _ time.Duration) error {
	if f.exactPutErr != nil {
		return f.exactPutErr
	}
	if f.exact == nil {
		f.exact = make(map[string]string)
	}
	f.exact[ruleID+"|"+key] = response
	return nil
}

type fakeCreator struct {
	emb   *embedding.Embedding
	err   error
	calls int
}

func (f *fakeCreator) Generate(context.Context, string, string, *embedding.Config) (*embedding.Embedding, error) {
	f.calls++
	return f.emb, f.err
}

func locatorWith(c embedding.Creator) embeddingfactory.EmbeddingServiceLocator {
	return embeddingfactory.NewServiceLocator(embeddingfactory.ProviderRegistry{defaultProvider: c})
}

// partitionStore keys stored entries by RuleID so a Lookup only ever returns
// candidates written under the same partition. It proves a consumer can never
// read another consumer's cached response.
type partitionStore struct {
	mu      sync.Mutex
	byRule  map[string][]semantic.Entry
	lookups int
}

func (s *partitionStore) EnsureIndex(context.Context, int) error { return nil }

func (s *partitionStore) Store(_ context.Context, e semantic.Entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.byRule == nil {
		s.byRule = make(map[string][]semantic.Entry)
	}
	s.byRule[e.RuleID] = append(s.byRule[e.RuleID], e)
	return nil
}

func (s *partitionStore) Lookup(_ context.Context, ruleID string, _ *embedding.Embedding, _ int) ([]semantic.Candidate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lookups++
	entries := s.byRule[ruleID]
	if len(entries) == 0 {
		return nil, nil
	}
	out := make([]semantic.Candidate, 0, len(entries))
	for _, e := range entries {
		out = append(out, semantic.Candidate{Response: e.Response, Similarity: 1.0})
	}
	return out, nil
}

func (s *partitionStore) GetExact(context.Context, string, string) (string, bool, error) {
	return "", false, nil
}

func (s *partitionStore) PutExact(context.Context, string, string, string, time.Duration) error {
	return nil
}

func (s *partitionStore) count(ruleID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.byRule[ruleID])
}

func settingsWith(extra map[string]any) map[string]any {
	s := baseSettings()
	for k, v := range extra {
		s[k] = v
	}
	return s
}

func TestExactKeyNormalization(t *testing.T) {
	const partition = "registry|c:consumer-1"

	assert.Equal(t, exactKey(partition, "Hello World"), exactKey(partition, "hello world"))
	assert.Equal(t, exactKey(partition, "hello   world"), exactKey(partition, "hello world"))
	assert.Equal(t, exactKey(partition, "  hello world  "), exactKey(partition, "hello world"))
	assert.Equal(t, exactKey(partition, "HELLO\tWORLD"), exactKey(partition, "hello world"))

	assert.NotEqual(t, exactKey(partition, "hello world"), exactKey(partition, "goodbye world"))
	assert.NotEqual(t, exactKey("a", "b"), exactKey("a|b", ""))
	assert.Len(t, exactKey(partition, "hello world"), 64)
}

func anEmbedding() *embedding.Embedding {
	return &embedding.Embedding{Value: []float64{0.1, 0.2, 0.3}}
}

func baseSettings() map[string]any {
	return map[string]any{
		"similarity_threshold": 0.8,
		"ttl":                  "1h",
		"embedding":            map[string]any{"provider": "openai", "model": "m", "api_key": "k"},
	}
}

func openAIBody() []byte {
	return []byte(`{"model":"gpt","messages":[{"role":"user","content":"hello world"}]}`)
}

func defaultScope() appplugins.RuntimeScope {
	return appplugins.RuntimeScope{ConsumerID: "c-1", GatewayID: "gw-1"}
}

func newInput(stage policy.Stage, req *infracontext.RequestContext, resp *infracontext.ResponseContext) appplugins.ExecInput {
	return appplugins.ExecInput{
		Stage:    stage,
		Config:   policy.PluginConfig{ID: "sc-1", Slug: PluginName, Name: PluginName, Settings: baseSettings()},
		Scope:    defaultScope(),
		Request:  req,
		Response: resp,
	}
}

func scopedInput(stage policy.Stage, settings map[string]any, req *infracontext.RequestContext, resp *infracontext.ResponseContext, scope appplugins.RuntimeScope) appplugins.ExecInput {
	in := newInput(stage, req, resp)
	in.Config.Settings = settings
	in.Scope = scope
	return in
}

func TestPlugin_StagesAndName(t *testing.T) {
	p := New(nil, nil, nil)
	assert.Equal(t, []policy.Stage{policy.StagePreRequest, policy.StagePostResponse}, p.MandatoryStages())
	assert.Equal(t, []policy.Stage{policy.StagePreRequest, policy.StagePostResponse}, p.SupportedStages())
	assert.Equal(t, PluginName, p.Name())
}

func TestPlugin_ValidateConfig(t *testing.T) {
	p := New(nil, nil, nil)
	require.NoError(t, p.ValidateConfig(baseSettings()))

	noKey := baseSettings()
	noKey["embedding"] = map[string]any{"provider": "openai", "model": "m"}
	require.NoError(t, p.ValidateConfig(noKey), "api_key must be optional")

	bad2 := baseSettings()
	bad2["similarity_threshold"] = 2.0
	require.Error(t, p.ValidateConfig(bad2))
}

func TestPlugin_NoCacheHeaderSkips(t *testing.T) {
	store := &fakeStore{}
	p := New(store, locatorWith(&fakeCreator{}), adapter.NewRegistry())
	req := &infracontext.RequestContext{Provider: "openai", Body: openAIBody(), Headers: map[string][]string{"Cache-Control": {"no-cache"}}}

	res, err := p.Execute(context.Background(), newInput(policy.StagePreRequest, req, &infracontext.ResponseContext{}))
	require.NoError(t, err)
	require.False(t, res.StopUpstream)
	assert.Equal(t, []string{"MISS"}, res.Headers["X-Cache"])
}

func TestPlugin_BypassHeaderSkips(t *testing.T) {
	store := &fakeStore{candidates: []semantic.Candidate{{Response: `{"cached":true}`, Similarity: 0.99}}}
	creator := &fakeCreator{emb: &embedding.Embedding{Value: []float64{0.1}}}
	p := New(store, locatorWith(creator), adapter.NewRegistry())

	req := &infracontext.RequestContext{
		Provider:   "openai",
		RegistryID: "b1",
		Body:       openAIBody(),
		Headers:    map[string][]string{"X-Cache-Bypass": {"1"}},
	}

	res, err := p.Execute(context.Background(), newInput(policy.StagePreRequest, req, &infracontext.ResponseContext{}))
	require.NoError(t, err)
	require.False(t, res.StopUpstream, "bypass header must prevent serving a hit")
	assert.Equal(t, []string{"MISS"}, res.Headers["X-Cache"])

	resp := &infracontext.ResponseContext{StatusCode: 200, Body: []byte(`{"answer":"hi"}`)}
	_, err = p.Execute(context.Background(), newInput(policy.StagePostResponse, req, resp))
	require.NoError(t, err)
	assert.Empty(t, store.stored, "bypass header must prevent storing")
}

func TestPlugin_PreRequest_HitShortCircuits(t *testing.T) {
	store := &fakeStore{candidates: []semantic.Candidate{{Response: `{"cached":true}`, Similarity: 0.95}}}
	creator := &fakeCreator{emb: &embedding.Embedding{Value: []float64{0.1, 0.2}}}
	p := New(store, locatorWith(creator), adapter.NewRegistry())

	req := &infracontext.RequestContext{Provider: "openai", RegistryID: "b1", Body: openAIBody()}
	resp := &infracontext.ResponseContext{}

	res, err := p.Execute(context.Background(), newInput(policy.StagePreRequest, req, resp))
	require.NoError(t, err)
	require.True(t, res.StopUpstream)
	assert.Equal(t, []byte(`{"cached":true}`), res.Body)
	assert.Equal(t, []string{"HIT"}, res.Headers["X-Cache"])
	assert.Equal(t, []string{"HIT"}, res.Headers["X-Cache-Status"])
	assert.Equal(t, cacheStatusHit, resp.Metadata[metadataCacheStatus])
}

func TestPlugin_PreRequest_ObserveDoesNotServeHit(t *testing.T) {
	store := &fakeStore{candidates: []semantic.Candidate{{Response: `{"cached":true}`, Similarity: 0.95}}}
	creator := &fakeCreator{emb: &embedding.Embedding{Value: []float64{0.1, 0.2}}}
	p := New(store, locatorWith(creator), adapter.NewRegistry())

	req := &infracontext.RequestContext{Provider: "openai", RegistryID: "b1", Body: openAIBody()}
	resp := &infracontext.ResponseContext{}

	in := newInput(policy.StagePreRequest, req, resp)
	in.Mode = policy.ModeObserve

	res, err := p.Execute(context.Background(), in)
	require.NoError(t, err)
	require.False(t, res.StopUpstream, "observe must not serve a cached response")
	assert.Nil(t, res.Body)
	assert.Equal(t, cacheStatusMiss, resp.Metadata[metadataCacheStatus])
}

func TestPlugin_PostResponse_ObserveDoesNotStore(t *testing.T) {
	store := &fakeStore{}
	creator := &fakeCreator{emb: &embedding.Embedding{Value: []float64{0.1, 0.2}}}
	p := New(store, locatorWith(creator), adapter.NewRegistry())

	req := &infracontext.RequestContext{Provider: "openai", RegistryID: "b1", Body: openAIBody()}
	resp := &infracontext.ResponseContext{StatusCode: 200, Body: []byte(`{"answer":"hi"}`)}

	in := newInput(policy.StagePostResponse, req, resp)
	in.Mode = policy.ModeObserve

	_, err := p.Execute(context.Background(), in)
	require.NoError(t, err)
	assert.Empty(t, store.stored, "observe must not write to the cache")
}

func TestPlugin_PreRequest_BelowThresholdMisses(t *testing.T) {
	store := &fakeStore{candidates: []semantic.Candidate{{Response: "x", Similarity: 0.5}}}
	creator := &fakeCreator{emb: &embedding.Embedding{Value: []float64{0.1}}}
	p := New(store, locatorWith(creator), adapter.NewRegistry())

	req := &infracontext.RequestContext{Provider: "openai", Body: openAIBody()}
	resp := &infracontext.ResponseContext{}

	res, err := p.Execute(context.Background(), newInput(policy.StagePreRequest, req, resp))
	require.NoError(t, err)
	require.False(t, res.StopUpstream)
	assert.Equal(t, cacheStatusMiss, resp.Metadata[metadataCacheStatus])
	assert.Equal(t, []string{"MISS"}, res.Headers["X-Cache"])
}

func TestPlugin_PreRequest_EmbeddingErrorDegrades(t *testing.T) {
	store := &fakeStore{}
	creator := &fakeCreator{err: errors.New("boom")}
	p := New(store, locatorWith(creator), adapter.NewRegistry())

	req := &infracontext.RequestContext{Provider: "openai", Body: openAIBody()}
	res, err := p.Execute(context.Background(), newInput(policy.StagePreRequest, req, &infracontext.ResponseContext{}))
	require.NoError(t, err)
	require.False(t, res.StopUpstream)
}

func TestPlugin_PreRequest_IndexErrorDegrades(t *testing.T) {
	store := &fakeStore{ensureErr: errors.New("no redisearch")}
	p := New(store, locatorWith(&fakeCreator{}), adapter.NewRegistry())

	req := &infracontext.RequestContext{Provider: "openai", Body: openAIBody()}
	res, err := p.Execute(context.Background(), newInput(policy.StagePreRequest, req, &infracontext.ResponseContext{}))
	require.NoError(t, err)
	require.False(t, res.StopUpstream)
}

func TestPlugin_PostResponse_StoresOnMiss(t *testing.T) {
	store := &fakeStore{}
	creator := &fakeCreator{emb: &embedding.Embedding{Value: []float64{0.1, 0.2}}}
	p := New(store, locatorWith(creator), adapter.NewRegistry())

	req := &infracontext.RequestContext{Provider: "openai", RegistryID: "b1", Body: openAIBody()}
	resp := &infracontext.ResponseContext{StatusCode: 200, Body: []byte(`{"answer":"hi"}`)}

	_, err := p.Execute(context.Background(), newInput(policy.StagePostResponse, req, resp))
	require.NoError(t, err)
	require.Len(t, store.stored, 1)
	assert.Equal(t, "b1|c:c-1", store.stored[0].RuleID)
	assert.Equal(t, `{"answer":"hi"}`, store.stored[0].Response)
	assert.Equal(t, time.Hour, store.stored[0].TTL)
}

func TestPlugin_PostResponse_SkipsOnHit(t *testing.T) {
	store := &fakeStore{}
	creator := &fakeCreator{emb: &embedding.Embedding{Value: []float64{0.1}}}
	p := New(store, locatorWith(creator), adapter.NewRegistry())

	req := &infracontext.RequestContext{Provider: "openai", Body: openAIBody()}
	resp := &infracontext.ResponseContext{StatusCode: 200, Body: []byte(`x`), Metadata: map[string]interface{}{metadataCacheStatus: cacheStatusHit}}

	_, err := p.Execute(context.Background(), newInput(policy.StagePostResponse, req, resp))
	require.NoError(t, err)
	assert.Empty(t, store.stored)
}

func TestPlugin_PostResponse_SkipsNon2xx(t *testing.T) {
	store := &fakeStore{}
	p := New(store, locatorWith(&fakeCreator{emb: &embedding.Embedding{Value: []float64{0.1}}}), adapter.NewRegistry())

	req := &infracontext.RequestContext{Provider: "openai", Body: openAIBody()}
	resp := &infracontext.ResponseContext{StatusCode: 500, Body: []byte(`err`)}

	_, err := p.Execute(context.Background(), newInput(policy.StagePostResponse, req, resp))
	require.NoError(t, err)
	assert.Empty(t, store.stored)
}

func TestPlugin_PostResponse_CacheOnlyOnStatus(t *testing.T) {
	creator := &fakeCreator{emb: &embedding.Embedding{Value: []float64{0.1, 0.2}}}
	cases := []struct {
		name       string
		statusCode int
		wantStored bool
	}{
		{name: "200 allowed", statusCode: 200, wantStored: true},
		{name: "201 blocked", statusCode: 201, wantStored: false},
		{name: "500 blocked", statusCode: 500, wantStored: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := &fakeStore{}
			p := New(store, locatorWith(creator), adapter.NewRegistry())

			settings := baseSettings()
			settings["cache_only_on_status"] = []any{200}

			req := &infracontext.RequestContext{Provider: "openai", RegistryID: "b1", Body: openAIBody()}
			resp := &infracontext.ResponseContext{StatusCode: tc.statusCode, Body: []byte(`{"answer":"hi"}`)}
			in := newInput(policy.StagePostResponse, req, resp)
			in.Config.Settings = settings

			_, err := p.Execute(context.Background(), in)
			require.NoError(t, err)
			if tc.wantStored {
				assert.Len(t, store.stored, 1)
			} else {
				assert.Empty(t, store.stored)
			}
		})
	}
}

func TestPartitionKey(t *testing.T) {
	consumer := &config{}
	global := &config{Scope: scopeGlobal}
	cases := []struct {
		name    string
		cfg     *config
		scope   appplugins.RuntimeScope
		req     *infracontext.RequestContext
		wantKey string
		wantOK  bool
	}{
		{
			name:    "consumer keys on consumer id",
			cfg:     consumer,
			scope:   appplugins.RuntimeScope{ConsumerID: "c1", GatewayID: "g1"},
			req:     &infracontext.RequestContext{RegistryID: "r1"},
			wantKey: "r1|c:c1",
			wantOK:  true,
		},
		{
			name:    "consumer second consumer is distinct",
			cfg:     consumer,
			scope:   appplugins.RuntimeScope{ConsumerID: "c2", GatewayID: "g1"},
			req:     &infracontext.RequestContext{RegistryID: "r1"},
			wantKey: "r1|c:c2",
			wantOK:  true,
		},
		{
			name:    "consumer empty id is pass-through",
			cfg:     consumer,
			scope:   appplugins.RuntimeScope{ConsumerID: "", GatewayID: "g1"},
			req:     &infracontext.RequestContext{RegistryID: "r1"},
			wantKey: "",
			wantOK:  false,
		},
		{
			name:    "consumer second registry is distinct",
			cfg:     consumer,
			scope:   appplugins.RuntimeScope{ConsumerID: "c1", GatewayID: "g1"},
			req:     &infracontext.RequestContext{RegistryID: "r2"},
			wantKey: "r2|c:c1",
			wantOK:  true,
		},
		{
			name:    "empty registry falls back to gateway",
			cfg:     consumer,
			scope:   appplugins.RuntimeScope{ConsumerID: "c1", GatewayID: "g1"},
			req:     &infracontext.RequestContext{GatewayID: "gwfb"},
			wantKey: "gwfb|c:c1",
			wantOK:  true,
		},
		{
			name:    "global keys on gateway id",
			cfg:     global,
			scope:   appplugins.RuntimeScope{ConsumerID: "c1", GatewayID: "gw"},
			req:     &infracontext.RequestContext{RegistryID: "r1"},
			wantKey: "r1|g:gw",
			wantOK:  true,
		},
		{
			name:    "global empty gateway is pass-through",
			cfg:     global,
			scope:   appplugins.RuntimeScope{ConsumerID: "c1", GatewayID: ""},
			req:     &infracontext.RequestContext{RegistryID: "r1"},
			wantKey: "",
			wantOK:  false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key, ok := partitionKey(tc.cfg, tc.scope, tc.req)
			assert.Equal(t, tc.wantOK, ok)
			assert.Equal(t, tc.wantKey, key)
		})
	}

	t.Run("global same gateway shares partition", func(t *testing.T) {
		a, okA := partitionKey(global, appplugins.RuntimeScope{GatewayID: "gw"}, &infracontext.RequestContext{RegistryID: "r1"})
		b, okB := partitionKey(global, appplugins.RuntimeScope{GatewayID: "gw"}, &infracontext.RequestContext{RegistryID: "r1"})
		require.True(t, okA)
		require.True(t, okB)
		assert.Equal(t, a, b)
	})
}

func TestPlugin_ConsumerScopeIsolatesConsumers(t *testing.T) {
	store := &partitionStore{}
	creator := &fakeCreator{emb: anEmbedding()}
	p := New(store, locatorWith(creator), adapter.NewRegistry())

	reqA := &infracontext.RequestContext{Provider: "openai", RegistryID: "reg", Body: openAIBody()}
	scopeA := appplugins.RuntimeScope{ConsumerID: "consumer-a", GatewayID: "gw"}
	respA := &infracontext.ResponseContext{StatusCode: 200, Body: []byte(`{"answer":"from-A"}`)}

	_, err := p.Execute(context.Background(), scopedInput(policy.StagePostResponse, baseSettings(), reqA, respA, scopeA))
	require.NoError(t, err)
	require.Equal(t, 1, store.count("reg|c:consumer-a"), "consumer A response must be stored under A's partition")

	reqB := &infracontext.RequestContext{Provider: "openai", RegistryID: "reg", Body: openAIBody()}
	scopeB := appplugins.RuntimeScope{ConsumerID: "consumer-b", GatewayID: "gw"}
	resB, err := p.Execute(context.Background(), scopedInput(policy.StagePreRequest, baseSettings(), reqB, &infracontext.ResponseContext{}, scopeB))
	require.NoError(t, err)
	require.False(t, resB.StopUpstream, "consumer B must not read consumer A's cached response")
	assert.Equal(t, []string{"MISS"}, resB.Headers["X-Cache"])

	resA, err := p.Execute(context.Background(), scopedInput(policy.StagePreRequest, baseSettings(), reqA, &infracontext.ResponseContext{}, scopeA))
	require.NoError(t, err)
	require.True(t, resA.StopUpstream, "consumer A must read its own cached response")
	assert.Equal(t, []byte(`{"answer":"from-A"}`), resA.Body)
}

func TestPlugin_EmptyConsumerPassesThrough(t *testing.T) {
	store := &partitionStore{}
	creator := &fakeCreator{emb: anEmbedding()}
	p := New(store, locatorWith(creator), adapter.NewRegistry())

	primed := &infracontext.RequestContext{Provider: "openai", RegistryID: "reg", Body: openAIBody()}
	primedScope := appplugins.RuntimeScope{ConsumerID: "consumer-a", GatewayID: "gw"}
	_, err := p.Execute(context.Background(), scopedInput(policy.StagePostResponse, baseSettings(), primed, &infracontext.ResponseContext{StatusCode: 200, Body: []byte(`{"answer":"x"}`)}, primedScope))
	require.NoError(t, err)
	require.Equal(t, 0, store.lookups, "store priming must not perform a lookup")

	anonReq := &infracontext.RequestContext{Provider: "openai", RegistryID: "reg", Body: openAIBody()}
	anonScope := appplugins.RuntimeScope{ConsumerID: "", GatewayID: "gw"}
	resPre, err := p.Execute(context.Background(), scopedInput(policy.StagePreRequest, baseSettings(), anonReq, &infracontext.ResponseContext{}, anonScope))
	require.NoError(t, err)
	require.False(t, resPre.StopUpstream)
	assert.Equal(t, []string{"MISS"}, resPre.Headers["X-Cache"])
	assert.Equal(t, 0, store.lookups, "empty consumer must not trigger a lookup (no cross-consumer leakage)")

	resPost, err := p.Execute(context.Background(), scopedInput(policy.StagePostResponse, baseSettings(), anonReq, &infracontext.ResponseContext{StatusCode: 200, Body: []byte(`{"answer":"leak"}`)}, anonScope))
	require.NoError(t, err)
	require.False(t, resPost.StopUpstream)
	assert.Equal(t, 0, store.count(""), "empty consumer must not store into a shared bucket")
}

func TestPlugin_GlobalScopeSharesGateway(t *testing.T) {
	store := &partitionStore{}
	creator := &fakeCreator{emb: anEmbedding()}
	p := New(store, locatorWith(creator), adapter.NewRegistry())

	settings := settingsWith(map[string]any{"scope": scopeGlobal})
	scope := appplugins.RuntimeScope{ConsumerID: "irrelevant", GatewayID: "gw-shared"}

	reqA := &infracontext.RequestContext{Provider: "openai", RegistryID: "reg", Body: openAIBody()}
	_, err := p.Execute(context.Background(), scopedInput(policy.StagePostResponse, settings, reqA, &infracontext.ResponseContext{StatusCode: 200, Body: []byte(`{"answer":"shared"}`)}, scope))
	require.NoError(t, err)
	require.Equal(t, 1, store.count("reg|g:gw-shared"))

	scopeB := appplugins.RuntimeScope{ConsumerID: "other-consumer", GatewayID: "gw-shared"}
	reqB := &infracontext.RequestContext{Provider: "openai", RegistryID: "reg", Body: openAIBody()}
	resB, err := p.Execute(context.Background(), scopedInput(policy.StagePreRequest, settings, reqB, &infracontext.ResponseContext{}, scopeB))
	require.NoError(t, err)
	require.True(t, resB.StopUpstream, "global scope shares one partition per gateway")
	assert.Equal(t, []byte(`{"answer":"shared"}`), resB.Body)
}

func streamingBody() []byte {
	return []byte(`{"model":"gpt","stream":true,"messages":[{"role":"user","content":"hello world"}]}`)
}

func TestPlugin_StreamingGate(t *testing.T) {
	t.Run("skip true blocks lookup on request stream", func(t *testing.T) {
		store := &fakeStore{candidates: []semantic.Candidate{{Response: `{"cached":true}`, Similarity: 0.99}}}
		p := New(store, locatorWith(&fakeCreator{emb: anEmbedding()}), adapter.NewRegistry())
		req := &infracontext.RequestContext{Provider: "openai", RegistryID: "b1", Body: streamingBody()}
		in := scopedInput(policy.StagePreRequest, settingsWith(map[string]any{"skip_if_streaming": true}), req, &infracontext.ResponseContext{}, defaultScope())

		res, err := p.Execute(context.Background(), in)
		require.NoError(t, err)
		require.False(t, res.StopUpstream, "streaming request must not be served from cache")
		assert.Equal(t, []string{"MISS"}, res.Headers["X-Cache"])
	})

	t.Run("skip true blocks store on response streaming", func(t *testing.T) {
		store := &fakeStore{}
		p := New(store, locatorWith(&fakeCreator{emb: anEmbedding()}), adapter.NewRegistry())
		req := &infracontext.RequestContext{Provider: "openai", RegistryID: "b1", Body: openAIBody()}
		resp := &infracontext.ResponseContext{StatusCode: 200, Body: []byte(`{"answer":"hi"}`), Streaming: true}
		in := scopedInput(policy.StagePostResponse, settingsWith(map[string]any{"skip_if_streaming": true}), req, resp, defaultScope())

		_, err := p.Execute(context.Background(), in)
		require.NoError(t, err)
		assert.Empty(t, store.stored, "streamed response must not be stored")
	})

	t.Run("skip false keeps serving a streaming request", func(t *testing.T) {
		store := &fakeStore{candidates: []semantic.Candidate{{Response: `{"cached":true}`, Similarity: 0.99}}}
		p := New(store, locatorWith(&fakeCreator{emb: anEmbedding()}), adapter.NewRegistry())
		req := &infracontext.RequestContext{Provider: "openai", RegistryID: "b1", Body: streamingBody()}
		in := scopedInput(policy.StagePreRequest, settingsWith(map[string]any{"skip_if_streaming": false}), req, &infracontext.ResponseContext{}, defaultScope())

		res, err := p.Execute(context.Background(), in)
		require.NoError(t, err)
		require.True(t, res.StopUpstream)
		assert.Equal(t, []string{"HIT"}, res.Headers["X-Cache"])
	})

	t.Run("skip true blocks lookup on gemini stream url", func(t *testing.T) {
		store := &fakeStore{candidates: []semantic.Candidate{{Response: `{"cached":true}`, Similarity: 0.99}}}
		p := New(store, locatorWith(&fakeCreator{emb: anEmbedding()}), adapter.NewRegistry())
		req := &infracontext.RequestContext{
			Provider:   "gemini",
			RegistryID: "b1",
			Path:       "/v1/models/gemini-pro:streamGenerateContent",
			Body:       openAIBody(),
		}
		in := scopedInput(policy.StagePreRequest, settingsWith(map[string]any{"skip_if_streaming": true}), req, &infracontext.ResponseContext{}, defaultScope())

		res, err := p.Execute(context.Background(), in)
		require.NoError(t, err)
		require.False(t, res.StopUpstream, "gemini streaming request must not be served from cache")
		assert.Equal(t, []string{"MISS"}, res.Headers["X-Cache"])
	})

	t.Run("skip true blocks lookup on alt sse query", func(t *testing.T) {
		store := &fakeStore{candidates: []semantic.Candidate{{Response: `{"cached":true}`, Similarity: 0.99}}}
		p := New(store, locatorWith(&fakeCreator{emb: anEmbedding()}), adapter.NewRegistry())
		req := &infracontext.RequestContext{
			Provider:   "gemini",
			RegistryID: "b1",
			Query:      url.Values{"alt": []string{"sse"}},
			Body:       openAIBody(),
		}
		in := scopedInput(policy.StagePreRequest, settingsWith(map[string]any{"skip_if_streaming": true}), req, &infracontext.ResponseContext{}, defaultScope())

		res, err := p.Execute(context.Background(), in)
		require.NoError(t, err)
		require.False(t, res.StopUpstream, "alt=sse streaming request must not be served from cache")
		assert.Equal(t, []string{"MISS"}, res.Headers["X-Cache"])
	})
}

func toolsRequestBody() []byte {
	return []byte(`{"model":"gpt","messages":[{"role":"user","content":"hello world"}],"tools":[{"type":"function","function":{"name":"get_weather"}}]}`)
}

func toolCallsResponseBody() []byte {
	return []byte(`{"choices":[{"message":{"role":"assistant","tool_calls":[{"id":"1","type":"function","function":{"name":"f","arguments":"{}"}}]},"finish_reason":"tool_calls"}]}`)
}

func TestPlugin_ToolsGate(t *testing.T) {
	t.Run("request tools skip serve and store", func(t *testing.T) {
		store := &fakeStore{candidates: []semantic.Candidate{{Response: `{"cached":true}`, Similarity: 0.99}}}
		p := New(store, locatorWith(&fakeCreator{emb: anEmbedding()}), adapter.NewRegistry())
		req := &infracontext.RequestContext{Provider: "openai", RegistryID: "b1", Body: toolsRequestBody()}

		res, err := p.Execute(context.Background(), scopedInput(policy.StagePreRequest, baseSettings(), req, &infracontext.ResponseContext{}, defaultScope()))
		require.NoError(t, err)
		require.False(t, res.StopUpstream, "tool request must not be served from cache")
		assert.Equal(t, []string{"MISS"}, res.Headers["X-Cache"])

		resp := &infracontext.ResponseContext{StatusCode: 200, Body: []byte(`{"answer":"hi"}`)}
		_, err = p.Execute(context.Background(), scopedInput(policy.StagePostResponse, baseSettings(), req, resp, defaultScope()))
		require.NoError(t, err)
		assert.Empty(t, store.stored, "tool request must not be stored")
	})

	t.Run("response tool_calls skip store", func(t *testing.T) {
		store := &fakeStore{}
		p := New(store, locatorWith(&fakeCreator{emb: anEmbedding()}), adapter.NewRegistry())
		req := &infracontext.RequestContext{Provider: "openai", RegistryID: "b1", Body: openAIBody()}
		resp := &infracontext.ResponseContext{StatusCode: 200, Body: toolCallsResponseBody()}

		_, err := p.Execute(context.Background(), scopedInput(policy.StagePostResponse, baseSettings(), req, resp, defaultScope()))
		require.NoError(t, err)
		assert.Empty(t, store.stored, "tool-call response must not be stored")
	})

	t.Run("explicit false caches despite tools", func(t *testing.T) {
		store := &fakeStore{candidates: []semantic.Candidate{{Response: `{"cached":true}`, Similarity: 0.99}}}
		p := New(store, locatorWith(&fakeCreator{emb: anEmbedding()}), adapter.NewRegistry())
		settings := settingsWith(map[string]any{"skip_if_tools_present": false})
		req := &infracontext.RequestContext{Provider: "openai", RegistryID: "b1", Body: toolsRequestBody()}

		res, err := p.Execute(context.Background(), scopedInput(policy.StagePreRequest, settings, req, &infracontext.ResponseContext{}, defaultScope()))
		require.NoError(t, err)
		require.True(t, res.StopUpstream, "explicit skip_if_tools_present=false must still serve cached hits")
		assert.Equal(t, []string{"HIT"}, res.Headers["X-Cache"])

		resp := &infracontext.ResponseContext{StatusCode: 200, Body: []byte(`{"answer":"hi"}`)}
		_, err = p.Execute(context.Background(), scopedInput(policy.StagePostResponse, settings, req, resp, defaultScope()))
		require.NoError(t, err)
		assert.Len(t, store.stored, 1, "explicit skip_if_tools_present=false must still store")
	})
}

func differentTextBody() []byte {
	return []byte(`{"model":"gpt","messages":[{"role":"user","content":"a completely different question"}]}`)
}

func normalizedVariantBody() []byte {
	return []byte(`{"model":"gpt","messages":[{"role":"user","content":"HELLO   World"}]}`)
}

func TestPlugin_ExactMode(t *testing.T) {
	const partition = "b1|c:c-1"
	exactSettings := settingsWith(map[string]any{"mode": modeExact})

	t.Run("normalized hit served without embedding", func(t *testing.T) {
		store := &fakeStore{ensureErr: errors.New("index must not be touched")}
		creator := &fakeCreator{emb: anEmbedding()}
		p := New(store, locatorWith(creator), adapter.NewRegistry())

		req := &infracontext.RequestContext{Provider: "openai", RegistryID: "b1", Body: openAIBody()}
		resp := &infracontext.ResponseContext{StatusCode: 200, Body: []byte(`{"answer":"hi"}`)}
		_, err := p.Execute(context.Background(), scopedInput(policy.StagePostResponse, exactSettings, req, resp, defaultScope()))
		require.NoError(t, err)

		hitReq := &infracontext.RequestContext{Provider: "openai", RegistryID: "b1", Body: normalizedVariantBody()}
		res, err := p.Execute(context.Background(), scopedInput(policy.StagePreRequest, exactSettings, hitReq, &infracontext.ResponseContext{}, defaultScope()))
		require.NoError(t, err)
		require.True(t, res.StopUpstream, "normalized exact match must serve from cache")
		assert.Equal(t, []byte(`{"answer":"hi"}`), res.Body)
		assert.Equal(t, []string{"HIT"}, res.Headers["X-Cache"])
		assert.Equal(t, []string{"HIT"}, res.Headers["X-Cache-Status"])
		assert.Empty(t, res.Headers["X-Cache-Similarity"], "exact hit must not emit a similarity header")
		assert.Equal(t, 0, creator.calls, "exact mode must never compute an embedding")
	})

	t.Run("different text misses without embedding", func(t *testing.T) {
		store := &fakeStore{ensureErr: errors.New("index must not be touched")}
		creator := &fakeCreator{emb: anEmbedding()}
		p := New(store, locatorWith(creator), adapter.NewRegistry())

		req := &infracontext.RequestContext{Provider: "openai", RegistryID: "b1", Body: openAIBody()}
		resp := &infracontext.ResponseContext{StatusCode: 200, Body: []byte(`{"answer":"hi"}`)}
		_, err := p.Execute(context.Background(), scopedInput(policy.StagePostResponse, exactSettings, req, resp, defaultScope()))
		require.NoError(t, err)
		require.Equal(t, `{"answer":"hi"}`, store.exact[partition+"|"+exactKey(partition, "hello world")])

		missReq := &infracontext.RequestContext{Provider: "openai", RegistryID: "b1", Body: differentTextBody()}
		res, err := p.Execute(context.Background(), scopedInput(policy.StagePreRequest, exactSettings, missReq, &infracontext.ResponseContext{}, defaultScope()))
		require.NoError(t, err)
		require.False(t, res.StopUpstream, "near-miss text must not serve a cached response")
		assert.Equal(t, []string{"MISS"}, res.Headers["X-Cache"])
		assert.Equal(t, 0, creator.calls, "exact mode must never compute an embedding")
	})

	t.Run("serves and stores without an embedding service", func(t *testing.T) {
		store := &fakeStore{}
		p := New(store, embeddingfactory.NewServiceLocator(embeddingfactory.ProviderRegistry{}), adapter.NewRegistry())
		noEmbed := map[string]any{"mode": modeExact, "similarity_threshold": 0.8}

		req := &infracontext.RequestContext{Provider: "openai", RegistryID: "b1", Body: openAIBody()}
		resp := &infracontext.ResponseContext{StatusCode: 200, Body: []byte(`{"answer":"hi"}`)}
		_, err := p.Execute(context.Background(), scopedInput(policy.StagePostResponse, noEmbed, req, resp, defaultScope()))
		require.NoError(t, err, "exact store must not require an embedding service")
		require.Len(t, store.exact, 1)

		res, err := p.Execute(context.Background(), scopedInput(policy.StagePreRequest, noEmbed, req, &infracontext.ResponseContext{}, defaultScope()))
		require.NoError(t, err, "exact serve must not require an embedding service")
		require.True(t, res.StopUpstream)
		assert.Equal(t, []byte(`{"answer":"hi"}`), res.Body)
	})
}

func TestPlugin_SemanticModeThreshold(t *testing.T) {
	t.Run("at or above threshold serves with similarity header", func(t *testing.T) {
		store := &fakeStore{candidates: []semantic.Candidate{{Response: `{"cached":true}`, Similarity: 0.97}}}
		creator := &fakeCreator{emb: anEmbedding()}
		p := New(store, locatorWith(creator), adapter.NewRegistry())
		settings := settingsWith(map[string]any{"mode": modeSemantic, "similarity_threshold": 0.95})

		req := &infracontext.RequestContext{Provider: "openai", RegistryID: "b1", Body: openAIBody()}
		res, err := p.Execute(context.Background(), scopedInput(policy.StagePreRequest, settings, req, &infracontext.ResponseContext{}, defaultScope()))
		require.NoError(t, err)
		require.True(t, res.StopUpstream, "0.97 >= 0.95 must serve")
		assert.Equal(t, []byte(`{"cached":true}`), res.Body)
		assert.Equal(t, []string{"HIT"}, res.Headers["X-Cache"])
		assert.Equal(t, []string{"0.9700"}, res.Headers["X-Cache-Similarity"])
	})

	t.Run("below threshold misses", func(t *testing.T) {
		store := &fakeStore{candidates: []semantic.Candidate{{Response: `{"cached":true}`, Similarity: 0.90}}}
		creator := &fakeCreator{emb: anEmbedding()}
		p := New(store, locatorWith(creator), adapter.NewRegistry())
		settings := settingsWith(map[string]any{"mode": modeSemantic, "similarity_threshold": 0.95})

		req := &infracontext.RequestContext{Provider: "openai", RegistryID: "b1", Body: openAIBody()}
		res, err := p.Execute(context.Background(), scopedInput(policy.StagePreRequest, settings, req, &infracontext.ResponseContext{}, defaultScope()))
		require.NoError(t, err)
		require.False(t, res.StopUpstream, "0.90 < 0.95 must miss")
		assert.Equal(t, []string{"MISS"}, res.Headers["X-Cache"])
	})
}

func TestPlugin_BothMode(t *testing.T) {
	const partition = "b1|c:c-1"
	bothSettings := settingsWith(map[string]any{"mode": modeBoth, "similarity_threshold": 0.95})

	t.Run("exact miss falls through to semantic hit", func(t *testing.T) {
		store := &fakeStore{candidates: []semantic.Candidate{{Response: `{"semantic":true}`, Similarity: 0.97}}}
		creator := &fakeCreator{emb: anEmbedding()}
		p := New(store, locatorWith(creator), adapter.NewRegistry())

		req := &infracontext.RequestContext{Provider: "openai", RegistryID: "b1", Body: openAIBody()}
		res, err := p.Execute(context.Background(), scopedInput(policy.StagePreRequest, bothSettings, req, &infracontext.ResponseContext{}, defaultScope()))
		require.NoError(t, err)
		require.True(t, res.StopUpstream, "no exact match must fall through to the semantic hit")
		assert.Equal(t, []byte(`{"semantic":true}`), res.Body)
		assert.Equal(t, []string{"HIT"}, res.Headers["X-Cache"])
		assert.Equal(t, []string{"0.9700"}, res.Headers["X-Cache-Similarity"])
		assert.Equal(t, 1, creator.calls, "both mode embeds only after an exact miss")
	})

	t.Run("store on miss writes both exact and semantic", func(t *testing.T) {
		store := &fakeStore{}
		creator := &fakeCreator{emb: anEmbedding()}
		p := New(store, locatorWith(creator), adapter.NewRegistry())

		req := &infracontext.RequestContext{Provider: "openai", RegistryID: "b1", Body: openAIBody()}
		resp := &infracontext.ResponseContext{StatusCode: 200, Body: []byte(`{"answer":"hi"}`)}
		_, err := p.Execute(context.Background(), scopedInput(policy.StagePostResponse, bothSettings, req, resp, defaultScope()))
		require.NoError(t, err)
		require.Len(t, store.stored, 1, "semantic entry must be stored")
		assert.Equal(t, `{"answer":"hi"}`, store.exact[partition+"|"+exactKey(partition, "hello world")], "exact entry must be stored")
	})

	t.Run("exact store failure does not fail the request", func(t *testing.T) {
		store := &fakeStore{exactPutErr: errors.New("exact down")}
		creator := &fakeCreator{emb: anEmbedding()}
		p := New(store, locatorWith(creator), adapter.NewRegistry())

		req := &infracontext.RequestContext{Provider: "openai", RegistryID: "b1", Body: openAIBody()}
		resp := &infracontext.ResponseContext{StatusCode: 200, Body: []byte(`{"answer":"hi"}`)}
		_, err := p.Execute(context.Background(), scopedInput(policy.StagePostResponse, bothSettings, req, resp, defaultScope()))
		require.NoError(t, err, "an exact store failure must not fail the request")
		require.Len(t, store.stored, 1, "the semantic store must still succeed when the exact store fails")
	})

	t.Run("semantic store failure does not fail the request", func(t *testing.T) {
		store := &fakeStore{storeErr: errors.New("semantic down")}
		creator := &fakeCreator{emb: anEmbedding()}
		p := New(store, locatorWith(creator), adapter.NewRegistry())

		req := &infracontext.RequestContext{Provider: "openai", RegistryID: "b1", Body: openAIBody()}
		resp := &infracontext.ResponseContext{StatusCode: 200, Body: []byte(`{"answer":"hi"}`)}
		_, err := p.Execute(context.Background(), scopedInput(policy.StagePostResponse, bothSettings, req, resp, defaultScope()))
		require.NoError(t, err, "a semantic store failure must not fail the request")
		assert.Equal(t, `{"answer":"hi"}`, store.exact[partition+"|"+exactKey(partition, "hello world")], "the exact store must still succeed when the semantic store fails")
	})
}

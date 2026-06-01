package semanticcache

import (
	"context"
	"errors"
	"testing"
	"time"

	appplugins "github.com/NeuralTrust/AgentGateway/pkg/app/plugins"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/embedding"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache/semantic"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	embeddingfactory "github.com/NeuralTrust/AgentGateway/pkg/infra/embedding/factory"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeStore struct {
	candidates []semantic.Candidate
	lookupErr  error
	stored     []semantic.Entry
	storeErr   error
	ensureErr  error
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

type fakeCreator struct {
	emb *embedding.Embedding
	err error
}

func (f *fakeCreator) Generate(context.Context, string, string, *embedding.Config) (*embedding.Embedding, error) {
	return f.emb, f.err
}

func locatorWith(c embedding.Creator) embeddingfactory.EmbeddingServiceLocator {
	return embeddingfactory.NewServiceLocator(embeddingfactory.ProviderRegistry{defaultProvider: c})
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

func newInput(stage policy.Stage, req *infracontext.RequestContext, resp *infracontext.ResponseContext) appplugins.ExecInput {
	return appplugins.ExecInput{
		Stage:    stage,
		Config:   policy.Plugin{ID: "sc-1", Name: PluginName, Settings: baseSettings()},
		Request:  req,
		Response: resp,
	}
}

func TestPlugin_StagesAndName(t *testing.T) {
	p := New(nil, nil, nil)
	assert.Equal(t, []policy.Stage{policy.StagePreRequest, policy.StagePostResponse}, p.Stages())
	assert.Equal(t, PluginName, p.Name())
}

func TestPlugin_ValidateConfig(t *testing.T) {
	p := New(nil, nil, nil)
	require.NoError(t, p.ValidateConfig(baseSettings()))

	bad := baseSettings()
	bad["embedding"] = map[string]any{"provider": "openai", "model": "m"} // missing api_key
	require.Error(t, p.ValidateConfig(bad))

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
}

func TestPlugin_PreRequest_HitShortCircuits(t *testing.T) {
	store := &fakeStore{candidates: []semantic.Candidate{{Response: `{"cached":true}`, Similarity: 0.95}}}
	creator := &fakeCreator{emb: &embedding.Embedding{Value: []float64{0.1, 0.2}}}
	p := New(store, locatorWith(creator), adapter.NewRegistry())

	req := &infracontext.RequestContext{Provider: "openai", BackendID: "b1", Body: openAIBody()}
	resp := &infracontext.ResponseContext{}

	res, err := p.Execute(context.Background(), newInput(policy.StagePreRequest, req, resp))
	require.NoError(t, err)
	require.True(t, res.StopUpstream)
	assert.Equal(t, []byte(`{"cached":true}`), res.Body)
	assert.Equal(t, []string{"HIT"}, res.Headers["X-Cache-Status"])
	assert.Equal(t, cacheStatusHit, resp.Metadata[metadataCacheStatus])
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

	req := &infracontext.RequestContext{Provider: "openai", BackendID: "b1", Body: openAIBody()}
	resp := &infracontext.ResponseContext{StatusCode: 200, Body: []byte(`{"answer":"hi"}`)}

	_, err := p.Execute(context.Background(), newInput(policy.StagePostResponse, req, resp))
	require.NoError(t, err)
	require.Len(t, store.stored, 1)
	assert.Equal(t, "b1", store.stored[0].RuleID)
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

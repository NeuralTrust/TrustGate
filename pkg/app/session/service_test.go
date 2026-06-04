package session_test

import (
	"context"
	"errors"
	"testing"
	"time"

	appsession "github.com/NeuralTrust/AgentGateway/pkg/app/session"
	"github.com/NeuralTrust/AgentGateway/pkg/config"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeRepo struct {
	saved    *domain.Session
	saveErr  error
	getResp  *domain.Session
	getErr   error
	getCalls int
}

func (f *fakeRepo) Save(_ context.Context, s *domain.Session) error {
	f.saved = s
	return f.saveErr
}

func (f *fakeRepo) Get(_ context.Context, _, _ string) (*domain.Session, error) {
	f.getCalls++
	return f.getResp, f.getErr
}

func enabledCfg(ttl time.Duration) *config.Config {
	return &config.Config{SessionStore: config.SessionStoreConfig{Enabled: true, TTL: ttl}}
}

func TestService_RecordPersistsTurnWithTTL(t *testing.T) {
	repo := &fakeRepo{}
	svc := appsession.NewService(repo, enabledCfg(30*time.Minute), nil)

	before := time.Now()
	svc.Record(context.Background(), appsession.RecordInput{
		GatewayID: "gw-1", SessionID: "sess-1", TurnID: "resp_1", Provider: "openai", Model: "gpt-4o",
	})

	require.NotNil(t, repo.saved)
	assert.Equal(t, "sess-1", repo.saved.ID)
	assert.Equal(t, "gw-1", repo.saved.GatewayID)
	assert.Equal(t, "resp_1", repo.saved.LastTurnID)
	assert.Equal(t, "openai", repo.saved.Provider)
	assert.Equal(t, "gpt-4o", repo.saved.Model)
	assert.WithinDuration(t, before.Add(30*time.Minute), repo.saved.ExpiresAt, time.Minute)
}

func TestService_RecordDefaultTTL(t *testing.T) {
	repo := &fakeRepo{}
	svc := appsession.NewService(repo, enabledCfg(0), nil)

	before := time.Now()
	svc.Record(context.Background(), appsession.RecordInput{GatewayID: "gw-1", SessionID: "sess-1", TurnID: "resp_1"})

	require.NotNil(t, repo.saved)
	assert.WithinDuration(t, before.Add(appsession.DefaultTTL), repo.saved.ExpiresAt, time.Minute)
}

func TestService_RecordNoopWithoutRequiredFields(t *testing.T) {
	repo := &fakeRepo{}
	svc := appsession.NewService(repo, enabledCfg(time.Hour), nil)

	svc.Record(context.Background(), appsession.RecordInput{GatewayID: "gw-1", SessionID: "sess-1"})
	svc.Record(context.Background(), appsession.RecordInput{SessionID: "sess-1", TurnID: "resp_1"})
	svc.Record(context.Background(), appsession.RecordInput{GatewayID: "gw-1", TurnID: "resp_1"})

	assert.Nil(t, repo.saved)
}

func TestService_DisabledNoops(t *testing.T) {
	repo := &fakeRepo{getResp: &domain.Session{LastTurnID: "resp_1"}}
	svc := appsession.NewService(repo, &config.Config{SessionStore: config.SessionStoreConfig{Enabled: false, TTL: time.Hour}}, nil)

	svc.Record(context.Background(), appsession.RecordInput{GatewayID: "gw-1", SessionID: "sess-1", TurnID: "resp_1"})
	assert.Nil(t, repo.saved)

	assert.Empty(t, svc.LastTurnID(context.Background(), "gw-1", "sess-1"))
	assert.Zero(t, repo.getCalls, "disabled store must not hit the repository")
}

func TestService_LastTurnID(t *testing.T) {
	repo := &fakeRepo{getResp: &domain.Session{LastTurnID: "resp_42"}}
	svc := appsession.NewService(repo, enabledCfg(time.Hour), nil)
	assert.Equal(t, "resp_42", svc.LastTurnID(context.Background(), "gw-1", "sess-1"))
}

func TestService_LastTurnIDMissOrError(t *testing.T) {
	miss := appsession.NewService(&fakeRepo{getResp: nil}, enabledCfg(time.Hour), nil)
	assert.Empty(t, miss.LastTurnID(context.Background(), "gw-1", "sess-1"))

	errored := appsession.NewService(&fakeRepo{getErr: errors.New("boom")}, enabledCfg(time.Hour), nil)
	assert.Empty(t, errored.LastTurnID(context.Background(), "gw-1", "sess-1"))
}

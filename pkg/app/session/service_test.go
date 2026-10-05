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

package session_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appsession "github.com/NeuralTrust/TrustGate/pkg/app/session"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeRepo struct {
	saved    *domain.Session
	saveErr  error
	getResp  *domain.Session
	getErr   error
	getCalls int
	turnResp string
	turnErr  error
}

func (f *fakeRepo) FindSessionIDByTurn(_ context.Context, _, _ string) (string, error) {
	return f.turnResp, f.turnErr
}

func (f *fakeRepo) Save(_ context.Context, s *domain.Session) error {
	f.saved = s
	return f.saveErr
}

func (f *fakeRepo) Get(_ context.Context, _, _ string) (*domain.Session, error) {
	f.getCalls++
	return f.getResp, f.getErr
}

var gw1 = appsession.Scope{GatewayID: "gw-1"}

func enabledCfg(ttl time.Duration) *config.Config {
	return &config.Config{SessionStore: config.SessionStoreConfig{Enabled: true, TTL: ttl}}
}

func TestService_RecordPersistsTurnWithTTL(t *testing.T) {
	repo := &fakeRepo{}
	svc := appsession.NewService(repo, enabledCfg(30*time.Minute), nil)

	before := time.Now()
	svc.Record(context.Background(), appsession.RecordInput{
		Scope: gw1, SessionID: "sess-1", TurnID: "resp_1", Provider: "openai", Model: "gpt-4o",
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
	svc.Record(context.Background(), appsession.RecordInput{Scope: gw1, SessionID: "sess-1", TurnID: "resp_1"})

	require.NotNil(t, repo.saved)
	assert.WithinDuration(t, before.Add(appsession.DefaultTTL), repo.saved.ExpiresAt, time.Minute)
}

func TestService_RecordNoopWithoutRequiredFields(t *testing.T) {
	repo := &fakeRepo{}
	svc := appsession.NewService(repo, enabledCfg(time.Hour), nil)

	svc.Record(context.Background(), appsession.RecordInput{Scope: gw1, SessionID: "sess-1"})
	svc.Record(context.Background(), appsession.RecordInput{SessionID: "sess-1", TurnID: "resp_1"})
	svc.Record(context.Background(), appsession.RecordInput{Scope: gw1, TurnID: "resp_1"})

	assert.Nil(t, repo.saved)
}

func TestService_DisabledNoops(t *testing.T) {
	repo := &fakeRepo{getResp: &domain.Session{LastTurnID: "resp_1"}}
	svc := appsession.NewService(repo, &config.Config{SessionStore: config.SessionStoreConfig{Enabled: false, TTL: time.Hour}}, nil)

	svc.Record(context.Background(), appsession.RecordInput{Scope: gw1, SessionID: "sess-1", TurnID: "resp_1"})
	assert.Nil(t, repo.saved)

	assert.Empty(t, svc.LastTurnID(context.Background(), gw1, "sess-1"))
	assert.Zero(t, repo.getCalls, "disabled store must not hit the repository")
}

func TestService_LastTurnID(t *testing.T) {
	repo := &fakeRepo{getResp: &domain.Session{LastTurnID: "resp_42"}}
	svc := appsession.NewService(repo, enabledCfg(time.Hour), nil)
	assert.Equal(t, "resp_42", svc.LastTurnID(context.Background(), gw1, "sess-1"))
}

func TestService_LastTurnIDMissOrError(t *testing.T) {
	miss := appsession.NewService(&fakeRepo{getResp: nil}, enabledCfg(time.Hour), nil)
	assert.Empty(t, miss.LastTurnID(context.Background(), gw1, "sess-1"))

	errored := appsession.NewService(&fakeRepo{getErr: errors.New("boom")}, enabledCfg(time.Hour), nil)
	assert.Empty(t, errored.LastTurnID(context.Background(), gw1, "sess-1"))
}

func TestService_SessionForTurn(t *testing.T) {
	hit := appsession.NewService(&fakeRepo{turnResp: "sess-1"}, enabledCfg(time.Hour), nil)
	assert.Equal(t, "sess-1", hit.SessionForTurn(context.Background(), "gw-1", "resp_1"))

	miss := appsession.NewService(&fakeRepo{}, enabledCfg(time.Hour), nil)
	assert.Empty(t, miss.SessionForTurn(context.Background(), "gw-1", "resp_1"))

	errored := appsession.NewService(&fakeRepo{turnResp: "sess-1", turnErr: errors.New("boom")}, enabledCfg(time.Hour), nil)
	assert.Empty(t, errored.SessionForTurn(context.Background(), "gw-1", "resp_1"))

	disabled := appsession.NewService(&fakeRepo{turnResp: "sess-1"}, &config.Config{SessionStore: config.SessionStoreConfig{Enabled: false}}, nil)
	assert.Empty(t, disabled.SessionForTurn(context.Background(), "gw-1", "resp_1"))
}

type memRepo struct {
	sessions map[string]domain.Session
	turns    map[string]string
	gets     []string
}

func newMemRepo() *memRepo {
	return &memRepo{sessions: map[string]domain.Session{}, turns: map[string]string{}}
}

func (m *memRepo) Save(_ context.Context, s *domain.Session) error {
	m.sessions[fmt.Sprintf("session:%s:%s", s.GatewayID, s.ID)] = *s
	m.turns[fmt.Sprintf("session_turn:%s:%s", s.GatewayID, s.LastTurnID)] = s.ID
	return nil
}

func (m *memRepo) Get(_ context.Context, gatewayID, sessionID string) (*domain.Session, error) {
	key := fmt.Sprintf("session:%s:%s", gatewayID, sessionID)
	m.gets = append(m.gets, key)
	s, ok := m.sessions[key]
	if !ok {
		return nil, nil
	}
	return &s, nil
}

func (m *memRepo) FindSessionIDByTurn(_ context.Context, gatewayID, turnID string) (string, error) {
	return m.turns[fmt.Sprintf("session_turn:%s:%s", gatewayID, turnID)], nil
}

func ownerCtx(owner string) context.Context {
	return appauth.WithAuthContext(context.Background(), &appauth.AuthContext{Method: appauth.MethodAPIKey, OwnerID: owner})
}

func TestService_OwnersNeverShareASession(t *testing.T) {
	repo := newMemRepo()
	svc := appsession.NewService(repo, enabledCfg(time.Hour), nil)
	alice := appsession.Scope{GatewayID: "gw-1", OwnerID: "alice"}
	bob := appsession.Scope{GatewayID: "gw-1", OwnerID: "bob"}
	svc.Record(context.Background(), appsession.RecordInput{Scope: alice, SessionID: "sess-1", TurnID: "resp_alice"})

	assert.Equal(t, "resp_alice", svc.LastTurnID(context.Background(), alice, "sess-1"))
	assert.Empty(t, svc.LastTurnID(context.Background(), bob, "sess-1"), "another owner naming the same session id")
	assert.Empty(t, svc.LastTurnID(context.Background(), gw1, "sess-1"), "an application key naming the same session id")
	assert.Empty(t, svc.LastTurnID(context.Background(), gw1, "/owner/alice:sess-1"), "a session id spelling the owner partition")
	assert.Empty(t, svc.LastTurnID(context.Background(), appsession.Scope{GatewayID: "gw-1", OwnerID: "alice:sess"}, "1"))

	svc.Record(context.Background(), appsession.RecordInput{Scope: bob, SessionID: "sess-1", TurnID: "resp_bob"})
	assert.Equal(t, "resp_alice", svc.LastTurnID(context.Background(), alice, "sess-1"))
	assert.Equal(t, "resp_bob", svc.LastTurnID(context.Background(), bob, "sess-1"))
}

func TestService_SessionForTurnStaysWithItsOwner(t *testing.T) {
	repo := newMemRepo()
	svc := appsession.NewService(repo, enabledCfg(time.Hour), nil)
	svc.Record(context.Background(), appsession.RecordInput{
		Scope: appsession.Scope{GatewayID: "gw-1", OwnerID: "alice"}, SessionID: "sess-a", TurnID: "resp_a",
	})
	svc.Record(context.Background(), appsession.RecordInput{Scope: gw1, SessionID: "sess-app", TurnID: "resp_app"})
	oidcAlice := appauth.WithAuthContext(context.Background(), &appauth.AuthContext{Method: appauth.MethodOIDC, OwnerID: "alice"})

	tests := []struct {
		name string
		ctx  context.Context
		turn string
		want string
	}{
		{name: "the owner's own turn", ctx: ownerCtx("alice"), turn: "resp_a", want: "sess-a"},
		{name: "another owner", ctx: ownerCtx("bob"), turn: "resp_a"},
		{name: "an application key", ctx: context.Background(), turn: "resp_a"},
		{name: "an owner on another method", ctx: oidcAlice, turn: "resp_a"},
		{name: "an application turn for an owner", ctx: ownerCtx("alice"), turn: "resp_app"},
		{name: "an application turn for an application key", ctx: context.Background(), turn: "resp_app", want: "sess-app"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, svc.SessionForTurn(tt.ctx, "gw-1", tt.turn))
		})
	}
}

func TestService_ApplicationKeysKeepTheirSessionKeys(t *testing.T) {
	repo := newMemRepo()
	svc := appsession.NewService(repo, enabledCfg(time.Hour), nil)
	svc.Record(context.Background(), appsession.RecordInput{Scope: gw1, SessionID: "sess-1", TurnID: "resp_1"})
	svc.LastTurnID(context.Background(), gw1, "sess-1")

	assert.Contains(t, repo.sessions, "session:gw-1:sess-1")
	assert.Equal(t, "sess-1", repo.turns["session_turn:gw-1:resp_1"])
	assert.Equal(t, []string{"session:gw-1:sess-1"}, repo.gets)
}

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

package session

import (
	"context"
	"log/slog"
	"net/url"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/session"
)

const DefaultTTL = time.Hour

const (
	writeTimeout  = 2 * time.Second
	lookupTimeout = 250 * time.Millisecond

	ownerPartition = "/owner/"
)

// Scope is whose conversations a session id names: a gateway's, narrowed to
// one key owner's when the request carries an owner, so two owners sending the
// same session id never read or extend each other's turns. A scope without an
// owner keys sessions exactly as before owners existed.
type Scope struct {
	GatewayID string
	OwnerID   string
}

func (s Scope) partition() string {
	if s.OwnerID == "" {
		return s.GatewayID
	}
	return s.GatewayID + ownerPartition + url.QueryEscape(s.OwnerID)
}

// RecordInput is the turn a request produced in a session.
type RecordInput struct {
	Scope
	SessionID string
	TurnID    string
	Provider  string
	Model     string
}

//go:generate mockery --name=Store --dir=. --output=./mocks --filename=store_mock.go --case=underscore --with-expecter
type Store interface {
	Record(ctx context.Context, in RecordInput)
	LastTurnID(ctx context.Context, scope Scope, sessionID string) string
	SessionForTurn(ctx context.Context, scope Scope, turnID string) string
}

var _ Store = (*Service)(nil)

type Service struct {
	repo    domain.Repository
	ttl     time.Duration
	enabled bool
	logger  *slog.Logger
}

func NewService(repo domain.Repository, cfg *config.Config, logger *slog.Logger) *Service {
	ttl := DefaultTTL
	enabled := true
	if cfg != nil {
		if cfg.SessionStore.TTL > 0 {
			ttl = cfg.SessionStore.TTL
		}
		enabled = cfg.SessionStore.Enabled
	}
	return &Service{repo: repo, ttl: ttl, enabled: enabled, logger: logger}
}

func (s *Service) Record(ctx context.Context, in RecordInput) {
	if !s.enabled || s.repo == nil || in.GatewayID == "" || in.SessionID == "" || in.TurnID == "" {
		return
	}
	now := time.Now()
	sess := &domain.Session{
		ID:         in.SessionID,
		GatewayID:  in.partition(),
		LastTurnID: in.TurnID,
		Provider:   in.Provider,
		Model:      in.Model,
		CreatedAt:  now,
		UpdatedAt:  now,
		ExpiresAt:  now.Add(s.ttl),
	}
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), writeTimeout)
	defer cancel()
	if err := s.repo.Save(writeCtx, sess); err != nil && s.logger != nil {
		s.logger.Debug("session store: save failed", slog.String("error", err.Error()))
	}
}

func (s *Service) LastTurnID(ctx context.Context, scope Scope, sessionID string) string {
	if !s.enabled || s.repo == nil || scope.GatewayID == "" || sessionID == "" {
		return ""
	}
	sess, err := s.repo.Get(ctx, scope.partition(), sessionID)
	if err != nil {
		if s.logger != nil {
			s.logger.Debug("session store: get failed", slog.String("error", err.Error()))
		}
		return ""
	}
	if sess == nil {
		return ""
	}
	return sess.LastTurnID
}

// SessionForTurn returns the session a previous provider turn was recorded
// under, so a continuation that only names the turn (OpenAI Responses
// previous_response_id) inherits its conversation. It runs on the request
// path, so the lookup is bounded and any failure reads as a miss. The turn is
// looked up in scope, so a turn recorded for another owner, or for no owner,
// is a miss.
func (s *Service) SessionForTurn(ctx context.Context, scope Scope, turnID string) string {
	if !s.enabled || s.repo == nil || scope.GatewayID == "" || turnID == "" {
		return ""
	}
	lookupCtx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()
	sessionID, err := s.repo.FindSessionIDByTurn(lookupCtx, scope.partition(), turnID)
	if err != nil {
		if s.logger != nil {
			s.logger.Debug("session store: turn lookup failed", slog.String("error", err.Error()))
		}
		return ""
	}
	return sessionID
}

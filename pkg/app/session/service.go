package session

import (
	"context"
	"log/slog"
	"time"

	"github.com/NeuralTrust/AgentGateway/pkg/config"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/session"
)

const DefaultTTL = time.Hour

const writeTimeout = 2 * time.Second

type RecordInput struct {
	GatewayID string
	SessionID string
	TurnID    string
	Provider  string
	Model     string
}

//go:generate mockery --name=Store --dir=. --output=./mocks --filename=store_mock.go --case=underscore --with-expecter
type Store interface {
	Record(ctx context.Context, in RecordInput)
	LastTurnID(ctx context.Context, gatewayID, sessionID string) string
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
		GatewayID:  in.GatewayID,
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

func (s *Service) LastTurnID(ctx context.Context, gatewayID, sessionID string) string {
	if !s.enabled || s.repo == nil || gatewayID == "" || sessionID == "" {
		return ""
	}
	sess, err := s.repo.Get(ctx, gatewayID, sessionID)
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

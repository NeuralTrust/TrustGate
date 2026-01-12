package auditlogs

import (
	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/audit-sdk-go"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

type Service interface {
	Emit(c *fiber.Ctx, event Event)
	Close() error
}

type service struct {
	enabled bool
	logger  *logrus.Logger
	client  audit.Client
}

func NewService(client audit.Client, logger *logrus.Logger, enabled bool) Service {
	return &service{
		enabled: enabled,
		logger:  logger,
		client:  client,
	}
}

func (s *service) Emit(c *fiber.Ctx, event Event) {
	if !s.enabled || s.client == nil {
		return
	}

	teamID, ok := c.Locals(string(common.TeamIDContextKey)).(string)
	if !ok || teamID == "" {
		s.logger.Warn("audit log skipped: missing team_id in context")
		return
	}

	userID, _ := c.Locals(string(common.UserIDContextKey)).(string)
	userEmail, _ := c.Locals(string(common.UserEmailContextKey)).(string)

	auditEvent := audit.Event{
		TeamID: teamID,
		Event: audit.EventInfo{
			Type:         event.Event.Type,
			Category:     event.Event.Category,
			Description:  event.Event.Description,
			Status:       event.Event.Status,
			ErrorMessage: event.Event.ErrorMessage,
		},
		Target: audit.Target{
			Type: event.Target.Type,
			ID:   event.Target.ID,
			Name: event.Target.Name,
		},
		Context: &audit.Context{
			IPAddress: event.Context.IPAddress,
			UserAgent: event.Context.UserAgent,
			SessionID: event.Context.SessionID,
			RequestID: event.Context.RequestID,
		},
	}

	if userID != "" {
		auditEvent.Actor = &audit.Actor{
			ID:    userID,
			Email: userEmail,
			Type:  audit.ActorTypeUser,
		}
	} else {
		auditEvent.Actor = &audit.Actor{
			ID:   "1",
			Type: audit.ActorTypeSystem,
		}
	}

	err := s.client.Emit(auditEvent)
	if err != nil {
		s.logger.Errorf("failed to emit audit event: %v", err)
	}
}

func (s *service) Close() error {
	if s.client != nil {
		return s.client.Close()
	}
	return nil
}

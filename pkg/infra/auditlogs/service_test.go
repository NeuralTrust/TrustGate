package auditlogs

import (
	"net/http/httptest"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/audit-sdk-go"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestNewService_Disabled(t *testing.T) {
	logger := logrus.New()

	svc := NewService(nil, logger, false)

	s := svc.(*service)
	assert.False(t, s.enabled)
	assert.Nil(t, s.client)
}

func TestNewService_WithClient(t *testing.T) {
	logger := logrus.New()
	mock := &mockClient{}

	svc := NewService(mock, logger, true)

	s := svc.(*service)
	assert.True(t, s.enabled)
	assert.Equal(t, mock, s.client)
}

func TestService_Emit_WhenDisabled(t *testing.T) {
	logger := logrus.New()
	svc := NewService(nil, logger, false)

	app := fiber.New()
	app.Get("/", func(c *fiber.Ctx) error {
		c.Locals(string(common.TeamIDContextKey), "team-123")
		svc.Emit(c, Event{
			Event: EventInfo{Type: "test"},
		})
		return nil
	})

	req := httptest.NewRequest("GET", "/", nil)
	_, _ = app.Test(req)
}

func TestService_Emit_Success(t *testing.T) {
	logger := logrus.New()
	mock := &mockClient{}
	svc := NewService(mock, logger, true)

	app := fiber.New()
	app.Get("/", func(c *fiber.Ctx) error {
		c.Locals(string(common.TeamIDContextKey), "team-123")
		c.Locals(string(common.UserIDContextKey), "user-456")
		svc.Emit(c, Event{
			Event: EventInfo{Type: "test.event", Category: "test"},
		})
		return nil
	})

	req := httptest.NewRequest("GET", "/", nil)
	_, _ = app.Test(req)

	assert.Len(t, mock.emittedEvents, 1)
	assert.Equal(t, "team-123", mock.emittedEvents[0].TeamID)
	assert.Equal(t, "user-456", mock.emittedEvents[0].Actor.ID)
	assert.Equal(t, audit.ActorTypeUser, mock.emittedEvents[0].Actor.Type)
}

func TestService_Emit_NoUserID_SystemActor(t *testing.T) {
	logger := logrus.New()
	mock := &mockClient{}
	svc := NewService(mock, logger, true)

	app := fiber.New()
	app.Get("/", func(c *fiber.Ctx) error {
		c.Locals(string(common.TeamIDContextKey), "team-123")
		svc.Emit(c, Event{
			Event: EventInfo{Type: "test.event", Category: "test"},
		})
		return nil
	})

	req := httptest.NewRequest("GET", "/", nil)
	_, _ = app.Test(req)

	assert.Len(t, mock.emittedEvents, 1)
	assert.Equal(t, "1", mock.emittedEvents[0].Actor.ID)
	assert.Equal(t, audit.ActorTypeSystem, mock.emittedEvents[0].Actor.Type)
}

func TestService_Emit_NoTeamID_Skipped(t *testing.T) {
	logger := logrus.New()
	mock := &mockClient{}
	svc := NewService(mock, logger, true)

	app := fiber.New()
	app.Get("/", func(c *fiber.Ctx) error {
		svc.Emit(c, Event{
			Event: EventInfo{Type: "test.event", Category: "test"},
		})
		return nil
	})

	req := httptest.NewRequest("GET", "/", nil)
	_, _ = app.Test(req)

	assert.Len(t, mock.emittedEvents, 0)
}

func TestService_Close_WhenDisabled(t *testing.T) {
	logger := logrus.New()
	svc := NewService(nil, logger, false)

	err := svc.Close()

	assert.NoError(t, err)
}

func TestService_Close_WithClient(t *testing.T) {
	logger := logrus.New()
	mock := &mockClient{}
	svc := NewService(mock, logger, true)

	err := svc.Close()

	assert.NoError(t, err)
	assert.True(t, mock.closed)
}

type mockClient struct {
	emittedEvents []audit.Event
	closed        bool
}

func (m *mockClient) Emit(event audit.Event) error {
	m.emittedEvents = append(m.emittedEvents, event)
	return nil
}

func (m *mockClient) Close() error {
	m.closed = true
	return nil
}

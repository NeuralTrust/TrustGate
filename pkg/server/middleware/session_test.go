package middleware

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

func TestSessionMiddleware_NoRule_PassesThrough(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel) // avoid "failed to get matched rule" log in this test
	m := NewSessionMiddleware(logger)

	app := fiber.New()
	app.Get("/", m.Middleware(), func(c *fiber.Ctx) error {
		sessionID := c.Locals(common.SessionContextKey)
		if sessionID != nil {
			t.Errorf("expected no session, got %v", sessionID)
		}
		return c.SendString("ok")
	})

	req := httptest.NewRequest("GET", "/", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestSessionMiddleware_RuleWithoutSessionConfig_PassesThrough(t *testing.T) {
	logger := logrus.New()
	m := NewSessionMiddleware(logger)

	rule := &types.ForwardingRuleDTO{ID: "r1", SessionConfig: nil}

	app := fiber.New()
	app.Get("/", func(c *fiber.Ctx) error {
		c.Locals(string(common.MatchedRuleContextKey), rule)
		return c.Next()
	}, m.Middleware(), func(c *fiber.Ctx) error {
		sessionID := c.Locals(common.SessionContextKey)
		if sessionID != nil {
			t.Errorf("expected no session when rule has no SessionConfig, got %v", sessionID)
		}
		return c.SendString("ok")
	})

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-TG-SESSION-ID", "sess-123")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestSessionMiddleware_ExtractsFromHeader(t *testing.T) {
	logger := logrus.New()
	m := NewSessionMiddleware(logger)

	rule := &types.ForwardingRuleDTO{
		ID: "r1",
		SessionConfig: &types.SessionConfigDTO{
			HeaderName:    "X-TG-SESSION-ID",
			BodyParamName: "tg_session_id",
		},
	}

	app := fiber.New()
	app.Get("/", func(c *fiber.Ctx) error {
		c.Locals(string(common.MatchedRuleContextKey), rule)
		return c.Next()
	}, m.Middleware(), func(c *fiber.Ctx) error {
		sessionID := c.Locals(common.SessionContextKey)
		if sessionID != "sess-from-header" {
			t.Errorf("expected session 'sess-from-header', got %v", sessionID)
		}
		return c.SendString("ok")
	})

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-TG-SESSION-ID", "sess-from-header")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestSessionMiddleware_ExtractsFromBody(t *testing.T) {
	logger := logrus.New()
	m := NewSessionMiddleware(logger)

	rule := &types.ForwardingRuleDTO{
		ID: "r1",
		SessionConfig: &types.SessionConfigDTO{
			HeaderName:    "X-TG-SESSION-ID",
			BodyParamName: "tg_session_id",
		},
	}

	app := fiber.New()
	app.Post("/", func(c *fiber.Ctx) error {
		c.Locals(string(common.MatchedRuleContextKey), rule)
		return c.Next()
	}, m.Middleware(), func(c *fiber.Ctx) error {
		sessionID := c.Locals(common.SessionContextKey)
		if sessionID != "sess-from-body" {
			t.Errorf("expected session 'sess-from-body', got %v", sessionID)
		}
		return c.SendString("ok")
	})

	body := map[string]interface{}{"tg_session_id": "sess-from-body"}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestSessionMiddleware_HeaderTakesPrecedenceOverBody(t *testing.T) {
	logger := logrus.New()
	m := NewSessionMiddleware(logger)

	rule := &types.ForwardingRuleDTO{
		ID: "r1",
		SessionConfig: &types.SessionConfigDTO{
			HeaderName:    "X-TG-SESSION-ID",
			BodyParamName: "tg_session_id",
		},
	}

	app := fiber.New()
	app.Post("/", func(c *fiber.Ctx) error {
		c.Locals(string(common.MatchedRuleContextKey), rule)
		return c.Next()
	}, m.Middleware(), func(c *fiber.Ctx) error {
		sessionID := c.Locals(common.SessionContextKey)
		if sessionID != "from-header" {
			t.Errorf("expected session 'from-header' (header precedence), got %v", sessionID)
		}
		return c.SendString("ok")
	})

	body := map[string]interface{}{"tg_session_id": "from-body"}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-TG-SESSION-ID", "from-header")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestSessionMiddleware_InvalidJSONBody_NoSessionSet(t *testing.T) {
	logger := logrus.New()
	m := NewSessionMiddleware(logger)

	rule := &types.ForwardingRuleDTO{
		ID: "r1",
		SessionConfig: &types.SessionConfigDTO{
			HeaderName:    "X-TG-SESSION-ID",
			BodyParamName: "tg_session_id",
		},
	}

	app := fiber.New()
	app.Post("/", func(c *fiber.Ctx) error {
		c.Locals(string(common.MatchedRuleContextKey), rule)
		return c.Next()
	}, m.Middleware(), func(c *fiber.Ctx) error {
		sessionID := c.Locals(common.SessionContextKey)
		if sessionID != nil {
			t.Errorf("expected no session with invalid JSON body, got %v", sessionID)
		}
		return c.SendString("ok")
	})

	req := httptest.NewRequest("POST", "/", bytes.NewReader([]byte("not valid json")))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestSessionMiddleware_SetsSessionInContext(t *testing.T) {
	logger := logrus.New()
	m := NewSessionMiddleware(logger)

	rule := &types.ForwardingRuleDTO{
		ID: "r1",
		SessionConfig: &types.SessionConfigDTO{
			HeaderName: "X-Session-ID",
		},
	}

	app := fiber.New()
	app.Get("/", func(c *fiber.Ctx) error {
		c.Locals(string(common.MatchedRuleContextKey), rule)
		return c.Next()
	}, m.Middleware(), func(c *fiber.Ctx) error {
		sessionID, ok := c.Context().Value(common.SessionContextKey).(string)
		if !ok || sessionID != "ctx-sess-1" {
			t.Errorf("expected session in context 'ctx-sess-1', got ok=%v sessionID=%v", ok, sessionID)
		}
		return c.SendString("ok")
	})

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Session-ID", "ctx-sess-1")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

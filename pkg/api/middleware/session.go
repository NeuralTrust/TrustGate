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

package middleware

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	appsession "github.com/NeuralTrust/TrustGate/pkg/app/session"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

const (
	defaultSessionHeader = "X-Session-Id"

	// Matches the firewall's own cap on conversation_id, which receives this id.
	maxSessionIDLen           = 256
	minWellKnownSessionIDLen  = 8
	maxSessionLookupBodyBytes = 8 << 20

	responsesConversationField     = "conversation"
	responsesPreviousResponseField = "previous_response_id"
)

// knownSessionHeaders are the conversation-id headers well-known clients
// already send, tried in order after the gateway's own header so an explicit
// configuration always wins. Without them every message of a client's
// conversation would look like a fresh session.
//
// session_id (Codex CLI) carries an underscore: ingress-nginx drops such
// headers unless enable-underscores-in-headers is on.
var knownSessionHeaders = []string{
	"X-Session-Id",
	"X-TG-Session-Id",
	"X-OpenWebUI-Chat-Id",
	"X-Claude-Code-Session-Id",
	"session_id",
	"session-id",
	"x-session-affinity",
	"Helicone-Session-Id",
	"x-litellm-session-id",
	"x-litellm-trace-id",
}

// legacySessionHeaders were accepted before the well-known list grew, with any
// value: they keep the lenient check so an existing client's short or free-form
// id is never silently dropped.
var legacySessionHeaders = []string{
	"X-Session-Id",
	"X-TG-Session-Id",
	"X-OpenWebUI-Chat-Id",
}

var (
	vendorSessionHeaderPattern = regexp.MustCompile(`^x-[a-z0-9-]+-session-id$`)
	wellKnownSessionIDPattern  = regexp.MustCompile(`^[A-Za-z0-9._:-]+$`)
)

// SessionMiddleware resolves the conversation id of every proxied request.
// See docs/sessions.md for the resolution order.
type SessionMiddleware struct {
	logger   *slog.Logger
	finder   appgateway.Finder
	sessions appsession.Store
}

func NewSessionMiddleware(
	logger *slog.Logger,
	finder appgateway.Finder,
	sessions appsession.Store,
) *SessionMiddleware {
	return &SessionMiddleware{logger: logger, finder: finder, sessions: sessions}
}

func (m *SessionMiddleware) Middleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		cfg := m.resolveConfig(c)
		if !cfg.IsEnabled() {
			return c.Next()
		}
		sess := m.resolve(c, cfg)
		c.SetUserContext(infracontext.WithSession(c.UserContext(), sess))
		c.Set(defaultSessionHeader, sess.ID)
		return c.Next()
	}
}

// EffectiveSessionID is the session id request consumers (telemetry, routing,
// guardrails, the session store) must use; empty for a hidden generated id.
func EffectiveSessionID(c *fiber.Ctx) string {
	return infracontext.EffectiveSessionID(c.UserContext())
}

func (m *SessionMiddleware) resolve(c *fiber.Ctx, cfg *domain.SessionConfig) infracontext.Session {
	headerName := defaultSessionHeader
	bodyParam := ""
	if cfg != nil {
		if cfg.HeaderName != "" {
			headerName = cfg.HeaderName
		}
		bodyParam = cfg.BodyParamName
	}

	if id, ok := configuredSessionID(c.Get(headerName)); ok {
		return exposedSession(id, infracontext.SessionSourceConfiguredHeader)
	}
	for _, name := range knownSessionHeaders {
		if strings.EqualFold(name, headerName) {
			continue
		}
		if id, ok := knownHeaderSessionID(name, c.Get(name)); ok {
			return exposedSession(id, infracontext.SessionSourceKnownHeader)
		}
	}
	if id, ok := vendorSessionHeader(c); ok {
		return exposedSession(id, infracontext.SessionSourcePatternHeader)
	}

	responses := isResponsesRequest(c)
	if bodyParam != "" || responses {
		if fields := m.bodyFields(c); fields != nil {
			if id, ok := bodySessionField(fields, bodyParam); ok {
				return exposedSession(id, infracontext.SessionSourceBodyField)
			}
			if responses {
				if id, ok := responsesConversationID(fields); ok {
					return exposedSession(id, infracontext.SessionSourceConversation)
				}
				if id, ok := m.previousResponseSession(c, fields); ok {
					return exposedSession(id, infracontext.SessionSourcePreviousResponse)
				}
			}
		}
	}

	return infracontext.Session{
		ID:      generateSessionID(),
		Source:  infracontext.SessionSourceGenerated,
		Exposed: responses,
	}
}

func exposedSession(id string, source infracontext.SessionSource) infracontext.Session {
	return infracontext.Session{ID: id, Source: source, Exposed: true}
}

func isResponsesRequest(c *fiber.Ctx) bool {
	route, ok := proxyRouteFor(c)
	return ok && route.SourceFormat == adapter.FormatOpenAIResponses
}

// configuredSessionID accepts any id up to maxSessionIDLen without control
// characters: the operator chose the source, and existing deployments rely on
// short ids.
func configuredSessionID(raw string) (string, bool) {
	id := strings.TrimSpace(raw)
	if id == "" || !utf8.ValidString(id) || utf8.RuneCountInString(id) > maxSessionIDLen {
		return "", false
	}
	if strings.IndexFunc(id, unicode.IsControl) >= 0 {
		return "", false
	}
	return id, true
}

// knownHeaderSessionID applies the lenient check to the headers the gateway
// already read before and the strict one to those it learned since.
func knownHeaderSessionID(name, raw string) (string, bool) {
	for _, legacy := range legacySessionHeaders {
		if strings.EqualFold(name, legacy) {
			return configuredSessionID(raw)
		}
	}
	return wellKnownSessionID(raw)
}

// wellKnownSessionID is stricter than configuredSessionID because the gateway
// guessed the source: a header that merely shares a name must not merge
// unrelated traffic into one session.
func wellKnownSessionID(raw string) (string, bool) {
	id := strings.TrimSpace(raw)
	if len(id) < minWellKnownSessionIDLen || len(id) > maxSessionIDLen || !wellKnownSessionIDPattern.MatchString(id) {
		return "", false
	}
	return id, true
}

func vendorSessionHeader(c *fiber.Ctx) (string, bool) {
	var names []string
	for key := range c.Request().Header.All() {
		name := strings.ToLower(string(key))
		if vendorSessionHeaderPattern.MatchString(name) && !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	for _, name := range names {
		if id, ok := wellKnownSessionID(c.Get(name)); ok {
			return id, true
		}
	}
	return "", false
}

func (m *SessionMiddleware) bodyFields(c *fiber.Ctx) map[string]json.RawMessage {
	body := c.Request().Body()
	if len(body) > maxSessionLookupBodyBytes {
		return nil
	}
	if len(c.Request().Header.ContentEncoding()) > 0 {
		body = c.Body()
		if len(body) > maxSessionLookupBodyBytes {
			return nil
		}
	}
	body = bytes.TrimSpace(body)
	if len(body) == 0 || body[0] != '{' {
		return nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		m.logger.Debug("session middleware: body is not valid JSON, skipping body lookup")
		return nil
	}
	return fields
}

func bodySessionField(fields map[string]json.RawMessage, name string) (string, bool) {
	if name == "" {
		return "", false
	}
	return configuredSessionID(jsonString(fields[name]))
}

// responsesConversationID reads the Conversations API id, sent either as a
// string or as an object {"id": "conv_..."}.
func responsesConversationID(fields map[string]json.RawMessage) (string, bool) {
	raw, ok := fields[responsesConversationField]
	if !ok {
		return "", false
	}
	if id, ok := wellKnownSessionID(jsonString(raw)); ok {
		return id, true
	}
	var obj struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return "", false
	}
	return wellKnownSessionID(obj.ID)
}

func (m *SessionMiddleware) previousResponseSession(c *fiber.Ctx, fields map[string]json.RawMessage) (string, bool) {
	if m.sessions == nil {
		return "", false
	}
	turnID, ok := wellKnownSessionID(jsonString(fields[responsesPreviousResponseField]))
	if !ok {
		return "", false
	}
	gatewayID, ok := appconsumer.GatewayIDFromContext(c.UserContext())
	if !ok {
		return "", false
	}
	return configuredSessionID(m.sessions.SessionForTurn(c.UserContext(), gatewayID.String(), turnID))
}

func jsonString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return ""
	}
	return s
}

func generateSessionID() string {
	if id, err := uuid.NewV7(); err == nil {
		return id.String()
	}
	return uuid.New().String()
}

func (m *SessionMiddleware) resolveConfig(c *fiber.Ctx) *domain.SessionConfig {
	if gw, ok := appgateway.FromContext(c.UserContext()); ok {
		if gw == nil {
			return nil
		}
		return gw.SessionConfig
	}
	gatewayID, ok := appconsumer.GatewayIDFromContext(c.UserContext())
	if !ok {
		return nil
	}
	gw, err := m.finder.FindByID(c.UserContext(), gatewayID)
	if err != nil {
		m.logger.Debug("session middleware: gateway lookup failed", slog.String("error", err.Error()))
		return nil
	}
	if gw == nil {
		return nil
	}
	return gw.SessionConfig
}

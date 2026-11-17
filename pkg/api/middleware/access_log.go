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
	"errors"
	"log/slog"
	"time"

	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/infra/logredact"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/requestid"
)

type AccessLogMiddleware struct {
	logger *slog.Logger
}

func NewAccessLogMiddleware(logger *slog.Logger) *AccessLogMiddleware {
	return &AccessLogMiddleware{logger: logger}
}

func (m *AccessLogMiddleware) Middleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		start := time.Now()
		err := c.Next()
		requestID, _ := c.Locals(requestid.ConfigDefault.ContextKey).(string)
		if requestID == "" {
			requestID = c.Get(HeaderTraceID)
		}

		// For streamed responses the body is a lazy fasthttp body stream
		// (registered via SetBodyStreamWriter). Calling Response.Body() here
		// would force fasthttp to drain the whole stream into memory before it
		// is flushed to the socket, collapsing chunk-by-chunk SSE delivery into
		// a single burst at end-of-stream. Skip the byte count in that case.
		bytesOut := -1
		if !c.Response().IsBodyStream() {
			bytesOut = len(c.Response().Body())
		}

		// When a handler returns an error, the app error handler writes the
		// real status only after this middleware unwinds; the response still
		// reads 200 here. Derive the status from the error instead.
		status := c.Response().StatusCode()
		attrs := []any{
			slog.String("method", c.Method()),
			slog.String("path", c.Path()),
			slog.Duration("duration", time.Since(start)),
			slog.String("request_id", requestID),
			slog.String("ip", c.IP()),
			slog.Int("bytes_out", bytesOut),
		}
		if identity := AdminIdentityFromContext(c); identity.Kind != "" {
			attrs = append(attrs,
				slog.String("identity_kind", string(identity.Kind)),
				slog.String("token_issuer", identity.Issuer),
			)
		}
		attrs = append(attrs, callerAttrs(c)...)
		if err != nil {
			status = fiber.StatusInternalServerError
			var fe *fiber.Error
			if errors.As(err, &fe) {
				status = fe.Code
			}
			attrs = append(attrs, slog.String("error", logredact.RedactLogString(err.Error())))
		}
		m.logger.Info("http access", append([]any{slog.Int("status", status)}, attrs...)...)
		return err
	}
}

// callerAttrs attributes a data-plane request to who made it, so the default
// access log answers "who sent this" without telemetry exporters or a debug
// level: the gateway, the consumer (application) it entered, the credential
// (auth id and how it authenticated), the subject it runs as and, for a
// bearer token, the client it was issued to. Every value comes from the
// verified identity the auth middleware attached, never from a header, and a
// field nobody resolved is left out. A person's email is not logged: the
// subject identifies them and telemetry carries the rest.
func callerAttrs(c *fiber.Ctx) []any {
	ctx := c.UserContext()
	var attrs []any
	if gatewayID, ok := appconsumer.GatewayIDFromContext(ctx); ok && !gatewayID.IsNil() {
		attrs = append(attrs, slog.String("gateway_id", gatewayID.String()))
	}
	if rc, ok := appconsumer.ConsumerFromContext(ctx); ok && rc.Consumer != nil {
		attrs = append(attrs, slog.String("consumer_id", rc.Consumer.ID.String()))
	}
	if authCtx, ok := appauth.AuthContextFromContext(ctx); ok {
		if !authCtx.AuthID.IsNil() {
			attrs = append(attrs, slog.String("auth_id", authCtx.AuthID.String()))
		}
		if authCtx.Method != "" {
			attrs = append(attrs, slog.String("auth_method", string(authCtx.Method)))
		}
	}
	if p := identity.PrincipalFromContext(ctx); p != nil {
		if p.Subject != "" {
			attrs = append(attrs, slog.String("principal_subject", p.Subject))
		}
		if p.Method != "" {
			attrs = append(attrs, slog.String("principal_method", string(p.Method)))
		}
		if p.Method.IsBearerToken() {
			if client := consumerdomain.ClientOfClaims(p.Claims); client != "" {
				attrs = append(attrs, slog.String("client_id", client))
			}
		}
	}
	return attrs
}

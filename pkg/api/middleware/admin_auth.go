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
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	"github.com/NeuralTrust/TrustGate/pkg/infra/auth/jwt"
	"github.com/gofiber/fiber/v2"
)

const (
	authorizationHeader = "Authorization"
	bearerPrefix        = "Bearer "
)

type AdminAuthMiddleware struct {
	logger                *slog.Logger
	jwtManager            jwt.Manager
	serviceVerifier       jwt.ServiceVerifier
	platformClaimRequired bool
}

func NewAdminAuthMiddleware(
	logger *slog.Logger,
	jwtManager jwt.Manager,
	serviceVerifier jwt.ServiceVerifier,
	platformClaimRequired bool,
) *AdminAuthMiddleware {
	return &AdminAuthMiddleware{
		logger:                logger,
		jwtManager:            jwtManager,
		serviceVerifier:       serviceVerifier,
		platformClaimRequired: platformClaimRequired,
	}
}

func (m *AdminAuthMiddleware) Middleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		authHeader := c.Get(authorizationHeader)
		if authHeader == "" {
			return m.unauthorized(c, "Authorization required", nil)
		}
		if !strings.HasPrefix(authHeader, bearerPrefix) {
			return m.unauthorized(c, "Invalid authorization format", nil)
		}

		tokenString := strings.TrimPrefix(authHeader, bearerPrefix)
		if tokenString == "" {
			return m.unauthorized(c, "Empty token provided", nil)
		}

		identity, err := m.resolveIdentity(tokenString)
		if err != nil {
			return m.unauthorized(c, err.message, err.cause)
		}

		StoreAdminIdentity(c, identity)
		return c.Next()
	}
}

// authFailure carries the generic wire message plus the underlying cause, which
// is only ever logged.
type authFailure struct {
	message string
	cause   error
}

// resolveIdentity routes the token to the verifier that matches its signing
// algorithm: asymmetric tokens are machine-to-machine credentials issued by the
// control plane, HMAC tokens are the console-issued admin tokens. Splitting on
// the algorithm keeps a service token from ever being validated against the
// shared secret, and vice versa.
func (m *AdminAuthMiddleware) resolveIdentity(tokenString string) (AdminIdentity, *authFailure) {
	if isAsymmetricToken(tokenString) {
		return m.resolveServiceIdentity(tokenString)
	}
	return m.resolveConsoleIdentity(tokenString)
}

func (m *AdminAuthMiddleware) resolveServiceIdentity(tokenString string) (AdminIdentity, *authFailure) {
	if m.serviceVerifier == nil || !m.serviceVerifier.Enabled() {
		return AdminIdentity{}, &authFailure{message: "Token not valid for admin API", cause: jwt.ErrServiceTokensDisabled}
	}
	claims, err := m.serviceVerifier.Verify(tokenString)
	if err != nil {
		return AdminIdentity{}, &authFailure{message: "Invalid token", cause: err}
	}
	return AdminIdentity{
		Kind:      AdminIdentityService,
		TenantID:  claims.TenantID,
		GatewayID: claims.GatewayID,
		Subject:   claims.Subject,
		Scopes:    claims.Scopes,
	}, nil
}

func (m *AdminAuthMiddleware) resolveConsoleIdentity(tokenString string) (AdminIdentity, *authFailure) {
	if err := m.jwtManager.ValidateToken(tokenString); err != nil {
		return AdminIdentity{}, &authFailure{message: "Invalid token", cause: err}
	}

	claims, err := m.jwtManager.DecodeToken(tokenString)
	if err != nil {
		return AdminIdentity{}, &authFailure{message: "Invalid token", cause: err}
	}

	// Purpose-tagged tokens (e.g. playground) are scoped to other planes
	// and must never grant admin access.
	if claims.Purpose != "" {
		return AdminIdentity{}, &authFailure{message: "Token not valid for admin API"}
	}

	// A service credential must be asymmetric and key-pinned; one minted with
	// the shared secret would bypass that guarantee.
	if claims.TokenUse != "" {
		return AdminIdentity{}, &authFailure{message: "Token not valid for admin API"}
	}

	identity := AdminIdentity{
		Kind:     AdminIdentityHuman,
		TenantID: claims.TenantID,
		Subject:  claims.UserID,
		Email:    claims.UserEmail,
	}
	if claims.TenantID != "" {
		return identity, nil
	}

	if m.platformClaimRequired && !claims.PlatformAdmin {
		return AdminIdentity{}, &authFailure{message: "Token not valid for admin API"}
	}
	identity.Kind = AdminIdentityPlatform
	return identity, nil
}

// isAsymmetricToken reports whether the JOSE header advertises a public-key
// algorithm. The header is untrusted routing information only: the selected
// verifier still pins the accepted algorithms before trusting any claim.
func isAsymmetricToken(tokenString string) bool {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(raw, &header); err != nil {
		return false
	}
	switch {
	case strings.HasPrefix(header.Alg, "RS"),
		strings.HasPrefix(header.Alg, "PS"),
		strings.HasPrefix(header.Alg, "ES"),
		header.Alg == "EdDSA":
		return true
	default:
		return false
	}
}

func (m *AdminAuthMiddleware) unauthorized(c *fiber.Ctx, message string, err error) error {
	m.logAuthFailure(c, message, err)
	return c.Status(fiber.StatusUnauthorized).JSON(httpio.ErrorBody{
		Error:   "unauthorized",
		Message: message,
	})
}

func (m *AdminAuthMiddleware) logAuthFailure(c *fiber.Ctx, reason string, err error) {
	if m.logger == nil {
		return
	}
	attrs := []slog.Attr{
		slog.String("reason", reason),
		slog.String("method", c.Method()),
		slog.String("path", c.Path()),
		slog.String("request_id", c.Get(fiber.HeaderXRequestID)),
	}
	if err != nil {
		attrs = append(attrs, slog.String("error", err.Error()))
	}
	m.logger.LogAttrs(c.UserContext(), slog.LevelDebug, "admin auth failed", attrs...)
}

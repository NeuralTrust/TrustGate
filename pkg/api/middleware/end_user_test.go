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
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/events"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// detected runs detectEndUser against a request carrying headers.
func detected(t *testing.T, headers map[string]string) *trace.EndUser {
	t.Helper()
	// Large enough to carry the oversized-token case to the handler.
	app := fiber.New(fiber.Config{ReadBufferSize: 16 * 1024})
	var got *trace.EndUser
	app.Post("/v1/chat/completions", func(c *fiber.Ctx) error {
		got = detectEndUser(c)
		return c.SendStatus(fiber.StatusOK)
	})
	req := httptest.NewRequest(fiber.MethodPost, "/v1/chat/completions", nil)
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	resp, err := app.Test(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	return got
}

func TestDetectEndUser_ReadsOpenWebUIHeaders(t *testing.T) {
	got := detected(t, map[string]string{
		"X-OpenWebUI-User-Id":    "u-42",
		"X-OpenWebUI-User-Email": "ana@acme.test",
		"X-OpenWebUI-User-Name":  "Ana",
		"X-OpenWebUI-User-Role":  "admin",
	})

	require.NotNil(t, got)
	assert.Equal(t, "u-42", got.ID)
	assert.Equal(t, "ana@acme.test", got.Email)
	assert.Equal(t, "Ana", got.Name)
	assert.Equal(t, "admin", got.Role)
	// The convention travels with the values so a reader can weigh them.
	assert.Equal(t, "open_webui", got.Source)
}

// Front-ends forward different subsets, and a partial claim still attributes
// better than none.
func TestDetectEndUser_AcceptsAPartialSet(t *testing.T) {
	got := detected(t, map[string]string{"X-OpenWebUI-User-Email": "ana@acme.test"})

	require.NotNil(t, got)
	assert.Equal(t, "ana@acme.test", got.Email)
	assert.Empty(t, got.ID)
	assert.Equal(t, "open_webui", got.Source)
}

// Our own namespace covers every client we do not know by name.
func TestDetectEndUser_ReadsTrustGateHeaders(t *testing.T) {
	got := detected(t, map[string]string{
		"X-TG-User-Id":    "u-42",
		"X-TG-User-Email": "ana@acme.test",
		"X-TG-User-Name":  "Ana",
		"X-TG-User-Role":  "admin",
	})

	require.NotNil(t, got)
	assert.Equal(t, "ana@acme.test", got.Email)
	assert.Equal(t, "admin", got.Role)
	assert.Equal(t, events.EndUserSourceTrustGate, got.Source)
}

// A customer setting our header did so on purpose; a vendor's own header is
// whatever its product happened to send.
func TestDetectEndUser_TrustGateHeadersOutrankAVendorConvention(t *testing.T) {
	got := detected(t, map[string]string{
		"X-TG-User-Email":        "configured@acme.test",
		"X-OpenWebUI-User-Email": "forwarded@acme.test",
	})

	require.NotNil(t, got)
	assert.Equal(t, "configured@acme.test", got.Email)
	assert.Equal(t, events.EndUserSourceTrustGate, got.Source)
}

// A set that contributed nothing is not a match, so a later one still gets read.
func TestDetectEndUser_FallsThroughAnEmptySet(t *testing.T) {
	got := detected(t, map[string]string{
		"X-TG-User-Email":        "   ",
		"X-OpenWebUI-User-Email": "ana@acme.test",
	})

	require.NotNil(t, got)
	assert.Equal(t, "ana@acme.test", got.Email)
	assert.Equal(t, events.EndUserSourceOpenWebUI, got.Source)
}

func TestDetectEndUser_NilWithoutKnownHeaders(t *testing.T) {
	assert.Nil(t, detected(t, nil))
	assert.Nil(t, detected(t, map[string]string{"X-Some-Other-Client-User": "ana@acme.test"}))
}

func TestDetectEndUser_IgnoresBlankValues(t *testing.T) {
	assert.Nil(t, detected(t, map[string]string{
		"X-OpenWebUI-User-Email": "   ",
		"X-OpenWebUI-User-Id":    "",
	}))
}

func TestDetectEndUser_TrimsValues(t *testing.T) {
	got := detected(t, map[string]string{"X-OpenWebUI-User-Email": "  ana@acme.test  "})

	require.NotNil(t, got)
	assert.Equal(t, "ana@acme.test", got.Email)
}

// The values are caller-supplied and unbounded; they end up as labels in
// telemetry, so an oversized one is truncated rather than stored whole.
func TestDetectEndUser_CapsOversizedValues(t *testing.T) {
	got := detected(t, map[string]string{
		"X-OpenWebUI-User-Name": strings.Repeat("a", maxEndUserValueLen*2),
	})

	require.NotNil(t, got)
	assert.Len(t, got.Name, maxEndUserValueLen)
}

func TestDetectEndUser_HeaderNamesAreCaseInsensitive(t *testing.T) {
	got := detected(t, map[string]string{"x-openwebui-user-email": "ana@acme.test"})

	require.NotNil(t, got)
	assert.Equal(t, "ana@acme.test", got.Email)
}

// openWebUIJWT mints the token Open WebUI sends when
// FORWARD_USER_INFO_HEADER_JWT_SECRET is set (utils/headers.py).
func openWebUIJWT(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("secret-only-open-webui-holds"))
	require.NoError(t, err)
	return token
}

func openWebUIClaims() jwt.MapClaims {
	now := time.Now().Unix()
	return jwt.MapClaims{
		"sub":   "u-42",
		"email": "ana@acme.test",
		"name":  "Ana",
		"role":  "admin",
		"iss":   "open-webui",
		"iat":   now,
		"exp":   now + 300,
	}
}

// With signing on, Open WebUI drops the plain headers and sends only the JWT.
func TestDetectEndUser_ReadsOpenWebUISignedJWT(t *testing.T) {
	got := detected(t, map[string]string{"X-OpenWebUI-User-Jwt": openWebUIJWT(t, openWebUIClaims())})

	require.NotNil(t, got)
	assert.Equal(t, "u-42", got.ID)
	assert.Equal(t, "ana@acme.test", got.Email)
	assert.Equal(t, "Ana", got.Name)
	assert.Equal(t, "admin", got.Role)
	assert.Equal(t, events.EndUserSourceOpenWebUI, got.Source)
}

// The gateway does not hold the secret, so an expired token still attributes:
// its claims are worth exactly what the plain headers were.
func TestDetectEndUser_ReadsAnExpiredOpenWebUIJWT(t *testing.T) {
	claims := openWebUIClaims()
	claims["exp"] = time.Now().Add(-time.Hour).Unix()

	got := detected(t, map[string]string{"X-OpenWebUI-User-Jwt": openWebUIJWT(t, claims)})

	require.NotNil(t, got)
	assert.Equal(t, "u-42", got.ID)
}

func TestDetectEndUser_IgnoresAJWTOpenWebUIDidNotIssue(t *testing.T) {
	claims := openWebUIClaims()
	claims["iss"] = "someone-else"

	assert.Nil(t, detected(t, map[string]string{"X-OpenWebUI-User-Jwt": openWebUIJWT(t, claims)}))
	assert.Nil(t, detected(t, map[string]string{"X-OpenWebUI-User-Jwt": "not-a-jwt"}))
	assert.Nil(t, detected(t, map[string]string{"X-OpenWebUI-User-Jwt": strings.Repeat("a", maxEndUserJWTLen+1)}))
}

func TestDetectEndUser_BoundsOpenWebUIJWTClaims(t *testing.T) {
	claims := openWebUIClaims()
	claims["email"] = strings.Repeat("a", maxEndUserValueLen+50)
	claims["role"] = 7 // not a string: dropped, not stringified

	got := detected(t, map[string]string{"X-OpenWebUI-User-Jwt": openWebUIJWT(t, claims)})

	require.NotNil(t, got)
	assert.Len(t, got.Email, maxEndUserValueLen)
	assert.Empty(t, got.Role)
}

// Plain headers a caller set outrank the token, as they outrank nothing else.
func TestDetectEndUser_TrustGateHeadersOutrankTheOpenWebUIJWT(t *testing.T) {
	got := detected(t, map[string]string{
		"X-TG-User-Email":      "configured@acme.test",
		"X-OpenWebUI-User-Jwt": openWebUIJWT(t, openWebUIClaims()),
	})

	require.NotNil(t, got)
	assert.Equal(t, "configured@acme.test", got.Email)
	assert.Equal(t, events.EndUserSourceTrustGate, got.Source)
}

// Open WebUI percent-encodes the name header (quote(name, safe=' ')).
func TestDetectEndUser_DecodesTheOpenWebUIName(t *testing.T) {
	got := detected(t, map[string]string{"X-OpenWebUI-User-Name": "Jos%C3%A9 Mar%C3%ADa"})
	require.NotNil(t, got)
	assert.Equal(t, "José María", got.Name)

	got = detected(t, map[string]string{"X-OpenWebUI-User-Name": "100%"})
	require.NotNil(t, got)
	assert.Equal(t, "100%", got.Name)
}

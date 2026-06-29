//go:build functional

package functional_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/infra/auth/jwt"
	golangjwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	playgroundTokenHeader = "X-AG-Playground-Token"
	traceIDHeader         = "X-AG-Trace-Id"
)

// mintPlaygroundToken signs a short-lived playground JWT bound to consumerSlug
// with the same secret the gateway boots with, mirroring what the dashboard BFF
// would mint.
func mintPlaygroundToken(t *testing.T, consumerSlug string) string {
	t.Helper()
	claims := &jwt.Claims{
		UserID:       "playground-user",
		Purpose:      jwt.PurposePlayground,
		ConsumerSlug: consumerSlug,
		RegisteredClaims: golangjwt.RegisteredClaims{
			IssuedAt:  golangjwt.NewNumericDate(time.Now()),
			ExpiresAt: golangjwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		},
	}
	token, err := golangjwt.NewWithClaims(golangjwt.SigningMethodHS256, claims).
		SignedString([]byte(GlobalConfig.Server.SecretKey))
	require.NoError(t, err)
	return token
}

// setupPlaygroundRoute wires a gateway with a single upstream and a consumer,
// returning the gateway slug (for discovery), the consumer routing path and the
// upstream so the test can drive a playground request end-to-end.
func setupPlaygroundRoute(t *testing.T) (gatewaySlug, consumerSlug, path string, up *fakeUpstream) {
	t.Helper()
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("pg-gw")})
	host, ok := gatewayHosts.Load(gatewayID)
	require.True(t, ok, "gateway host missing for %s", gatewayID)
	gatewaySlug = strings.TrimSuffix(host.(string), "."+functionalGatewayBaseDomain)
	require.NotEmpty(t, gatewaySlug)

	up = newJSONUpstream(t, "playground-upstream")
	registryID := CreateRegistry(t, gatewayID, openaiBackendPayload(uniqueName("pg-be"), up.URL()))

	coID := CreateConsumer(t, gatewayID, map[string]any{"name": uniqueName("pg-co")})
	AttachRegistry(t, gatewayID, coID, registryID)
	consumerSlug = ConsumerSlug(t, coID)
	path = chatCompletionsPath(t, coID)
	return gatewaySlug, consumerSlug, path, up
}

// playgroundPost forwards body through the proxy plane authenticating with a
// playground token (no api key) and identifying the gateway via the slug header.
func playgroundPost(t *testing.T, gatewaySlug, token, path string, body any) (int, http.Header, []byte) {
	t.Helper()
	buf, err := json.Marshal(body)
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost, ProxyURL+path, bytes.NewReader(buf))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(gatewaySlugHeader, gatewaySlug)
	req.Header.Set(playgroundTokenHeader, token)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, resp.Header, raw
}

// getPlaygroundTrace fetches a stored trace from the admin plane with the admin
// JWT, returning the raw body so callers can assert on redaction.
func getPlaygroundTrace(t *testing.T, traceID string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, AdminURL+"/v1/playground/traces/"+traceID, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+AdminToken)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, raw
}

// pollPlaygroundTrace retries the admin fetch until the asynchronously written
// Event shows up (200) or the budget is exhausted.
func pollPlaygroundTrace(t *testing.T, traceID string) []byte {
	t.Helper()
	var lastStatus int
	var lastBody []byte
	for i := 0; i < 60; i++ {
		lastStatus, lastBody = getPlaygroundTrace(t, traceID)
		if lastStatus == http.StatusOK {
			return lastBody
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("trace %s never became available (last status %d, body %s)", traceID, lastStatus, lastBody)
	return nil
}

func TestPlaygroundTraceE2E(t *testing.T) {
	defer Track(t, "PlaygroundTrace")()

	t.Run("stored playground trace is retrievable by trace id", func(t *testing.T) {
		gatewaySlug, consumerSlug, path, up := setupPlaygroundRoute(t)
		token := mintPlaygroundToken(t, consumerSlug)

		status, headers, body := playgroundPost(t, gatewaySlug, token, path, chatRequest(false))
		require.Equal(t, http.StatusOK, status, "playground request must succeed, body: %s", body)
		assert.Contains(t, string(body), "playground-upstream")
		assert.Equal(t, 1, up.Hits())

		traceID := headers.Get(traceIDHeader)
		require.NotEmpty(t, traceID, "proxy must echo the %s header", traceIDHeader)

		raw := pollPlaygroundTrace(t, traceID)

		var evt struct {
			TraceID   string `json:"trace_id"`
			GatewayID string `json:"gateway_id"`
			Status    struct {
				Code int `json:"code"`
			} `json:"status"`
			Request struct {
				Path string `json:"path"`
			} `json:"request"`
		}
		require.NoError(t, json.Unmarshal(raw, &evt), "trace body: %s", raw)
		assert.Equal(t, traceID, evt.TraceID, "stored TraceID must equal the echoed trace id")
		assert.NotEmpty(t, evt.GatewayID)
		assert.Equal(t, http.StatusOK, evt.Status.Code)
		assert.Contains(t, evt.Request.Path, "/v1/chat/completions")

		assert.NotContains(t, string(raw), token,
			"the playground token must never be stored in cleartext")
		assert.Contains(t, string(raw), "[REDACTED]",
			"sensitive headers must be redacted in the stored trace")
	})

	t.Run("unknown trace id returns 404", func(t *testing.T) {
		status, _ := getPlaygroundTrace(t, uuid.NewString())
		assert.Equal(t, http.StatusNotFound, status)
	})

	t.Run("non-playground request is not stored", func(t *testing.T) {
		up := newJSONUpstream(t, "regular-upstream")
		apiKey, path := setupRoute(t, "", up)

		status, headers, body := proxyPost(t, apiKey, path, chatRequest(false))
		require.Equal(t, http.StatusOK, status, "body: %s", body)

		traceID := headers.Get(traceIDHeader)
		require.NotEmpty(t, traceID, "proxy must echo the %s header for every request", traceIDHeader)

		var lastStatus int
		for i := 0; i < 30; i++ {
			lastStatus, _ = getPlaygroundTrace(t, traceID)
			if lastStatus == http.StatusOK {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		assert.Equal(t, http.StatusNotFound, lastStatus,
			"a request without a playground token must not be stored")
	})
}

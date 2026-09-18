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
	"context"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	appratelimit "github.com/NeuralTrust/TrustGate/pkg/app/ratelimit"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type recordingPlaneLimiter struct {
	classes  []appratelimit.PlaneClass
	subjects []string
	err      error
}

func (l *recordingPlaneLimiter) Check(
	_ context.Context,
	class appratelimit.PlaneClass,
	subject string,
) error {
	l.classes = append(l.classes, class)
	l.subjects = append(l.subjects, subject)
	return l.err
}

func planeApp(t *testing.T, limiter appratelimit.PlaneLimiter, enabled bool) *fiber.App {
	t.Helper()
	app := fiber.New()
	m := NewMCPPlaneRateLimitMiddleware(
		limiter,
		func(peer, _ string) string { return peer },
		enabled,
		nil,
	)
	app.Use(m.Middleware())
	app.All("/*", func(c *fiber.Ctx) error { return c.SendString("reached") })
	return app
}

func planeRequest(t *testing.T, app *fiber.App, method, target string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	req.Host = "gw.example.ai"
	resp, err := app.Test(req)
	require.NoError(t, err)
	recorder := httptest.NewRecorder()
	recorder.Code = resp.StatusCode
	for key, values := range resp.Header {
		for _, value := range values {
			recorder.Header().Add(key, value)
		}
	}
	return recorder
}

// The routes worth guessing at are the ones that answer before a credential is
// known, so they are counted apart from the plane's read-mostly traffic.
func TestClassifyPlaneRoute(t *testing.T) {
	credential := []string{
		"/oauth/token",
		"/oauth/register",
		"/oauth/register/client-123",
		"/oauth/authorize",
		"/oauth/callback",
		"/whoami",
	}
	for _, path := range credential {
		assert.Equal(t, appratelimit.PlaneClassCredential, classifyPlaneRoute(path), path)
	}

	standard := []string{
		"/.well-known/oauth-protected-resource",
		"/.well-known/oauth-authorization-server",
		"/.well-known/jwks.json",
		"/oauth/brands/linear.svg",
		"/support-bot/mcp",
		"/support-bot/connect",
		"/+/configure",
	}
	for _, path := range standard {
		assert.Equal(t, appratelimit.PlaneClassDefault, classifyPlaneRoute(path), path)
	}
}

func TestMCPPlaneRateLimitAllowsWhenUnderLimit(t *testing.T) {
	limiter := &recordingPlaneLimiter{}
	resp := planeRequest(t, planeApp(t, limiter, true), fiber.MethodPost, "/oauth/token")

	assert.Equal(t, fiber.StatusOK, resp.Code)
	require.Len(t, limiter.classes, 1)
	assert.Equal(t, appratelimit.PlaneClassCredential, limiter.classes[0])
}

// The host is part of the subject: one gateway being flooded must not spend
// another's allowance on a deployment that serves both.
func TestMCPPlaneRateLimitKeysOnHostAndSource(t *testing.T) {
	limiter := &recordingPlaneLimiter{}
	planeRequest(t, planeApp(t, limiter, true), fiber.MethodGet, "/whoami")

	require.Len(t, limiter.subjects, 1)
	assert.Contains(t, limiter.subjects[0], "gw.example.ai|")
}

func TestMCPPlaneRateLimitRefusesWithRetryAfter(t *testing.T) {
	limiter := &recordingPlaneLimiter{
		err: &appratelimit.PlaneLimitExceeded{RetryAfter: 30 * time.Second},
	}
	resp := planeRequest(t, planeApp(t, limiter, true), fiber.MethodPost, "/oauth/register")

	assert.Equal(t, fiber.StatusTooManyRequests, resp.Code)
	assert.Equal(t, "30", resp.Header().Get(fiber.HeaderRetryAfter))
	assert.Equal(t, "no-store", resp.Header().Get(fiber.HeaderCacheControl))
}

// A sub-second remainder still has to round up to a whole second, or the
// header invites a retry the bucket refuses again.
func TestMCPPlaneRateLimitRetryAfterIsAtLeastOneSecond(t *testing.T) {
	limiter := &recordingPlaneLimiter{
		err: &appratelimit.PlaneLimitExceeded{RetryAfter: 200 * time.Millisecond},
	}
	resp := planeRequest(t, planeApp(t, limiter, true), fiber.MethodPost, "/oauth/token")

	assert.Equal(t, "1", resp.Header().Get(fiber.HeaderRetryAfter))
}

// Redis blinking must not take the plane down with it.
func TestMCPPlaneRateLimitFailsOpenWhenCounterUnavailable(t *testing.T) {
	limiter := &recordingPlaneLimiter{err: appratelimit.ErrPlaneLimiterUnavailable}
	resp := planeRequest(t, planeApp(t, limiter, true), fiber.MethodPost, "/oauth/token")

	assert.Equal(t, fiber.StatusOK, resp.Code)
}

func TestMCPPlaneRateLimitFailsOpenOnAnyOtherError(t *testing.T) {
	limiter := &recordingPlaneLimiter{err: errors.New("dial tcp: connection refused")}
	resp := planeRequest(t, planeApp(t, limiter, true), fiber.MethodGet, "/whoami")

	assert.Equal(t, fiber.StatusOK, resp.Code)
}

func TestMCPPlaneRateLimitDisabledSkipsTheCounter(t *testing.T) {
	limiter := &recordingPlaneLimiter{
		err: &appratelimit.PlaneLimitExceeded{RetryAfter: time.Minute},
	}
	resp := planeRequest(t, planeApp(t, limiter, false), fiber.MethodPost, "/oauth/token")

	assert.Equal(t, fiber.StatusOK, resp.Code)
	assert.Empty(t, limiter.classes)
}

// An origin we cannot name is not one to guess about: let auth judge it.
func TestMCPPlaneRateLimitSkipsWhenSourceIsUnknown(t *testing.T) {
	limiter := &recordingPlaneLimiter{}
	app := fiber.New()
	m := NewMCPPlaneRateLimitMiddleware(
		limiter,
		func(string, string) string { return "" },
		true,
		nil,
	)
	app.Use(m.Middleware())
	app.All("/*", func(c *fiber.Ctx) error { return c.SendString("reached") })

	resp := planeRequest(t, app, fiber.MethodPost, "/oauth/token")

	assert.Equal(t, fiber.StatusOK, resp.Code)
	assert.Empty(t, limiter.classes)
}

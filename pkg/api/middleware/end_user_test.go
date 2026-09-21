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

	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// detected runs detectEndUser against a request carrying headers.
func detected(t *testing.T, headers map[string]string) *trace.EndUser {
	t.Helper()
	app := fiber.New()
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

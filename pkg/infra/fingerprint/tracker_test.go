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

package fingerprint_test

import (
	"net/http/httptest"
	"testing"

	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/fingerprint"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"
)

func captureFingerprint(t *testing.T, setup func(*fiber.Ctx)) fingerprint.Fingerprint {
	t.Helper()
	tracker := fingerprint.NewFingerPrintTracker()
	app := fiber.New()
	var captured fingerprint.Fingerprint
	app.Get("/", func(c *fiber.Ctx) error {
		setup(c)
		captured = tracker.MakeFingerprint(c)
		return c.SendStatus(fiber.StatusOK)
	})
	resp, err := app.Test(httptest.NewRequest(fiber.MethodGet, "/", nil))
	require.NoError(t, err)
	require.Equal(t, fiber.StatusOK, resp.StatusCode)
	return captured
}

func TestMakeFingerprint_KeepsClientSession(t *testing.T) {
	fp := captureFingerprint(t, func(c *fiber.Ctx) {
		c.Locals(string(infracontext.SessionContextKey), "sess-client")
	})
	require.Equal(t, "sess-client", fp.SessionID)
}

func TestMakeFingerprint_IgnoresGeneratedSession(t *testing.T) {
	fp := captureFingerprint(t, func(c *fiber.Ctx) {
		c.Locals(string(infracontext.SessionContextKey), "sess-generated")
		c.Locals(string(infracontext.SessionGeneratedContextKey), true)
	})
	require.Empty(t, fp.SessionID, "gateway-generated session ids must not feed the fingerprint")
}

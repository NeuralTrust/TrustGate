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

package httpio_test

import (
	"io"
	"net/http/httptest"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteBedrockError_MergesTheEnvelopeIntoTheGatewayBody(t *testing.T) {
	app := fiber.New()
	app.Get("/", func(c *fiber.Ctx) error {
		return httpio.WriteBedrockError(c, fiber.StatusForbidden, httpio.ErrorBody{Error: "forbidden", Message: "no"})
	})
	resp, err := app.Test(httptest.NewRequest(fiber.MethodGet, "/", nil))
	require.NoError(t, err)
	raw, _ := io.ReadAll(resp.Body)

	assert.Equal(t, fiber.StatusForbidden, resp.StatusCode)
	assert.Equal(t, "AccessDeniedException", resp.Header.Get("X-Amzn-Errortype"))
	assert.JSONEq(t, `{"__type":"AccessDeniedException","message":"no","error":"forbidden"}`, string(raw))
}

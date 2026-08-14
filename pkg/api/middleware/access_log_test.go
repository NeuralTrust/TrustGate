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
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"
)

func TestAccessLogConnectOutcomesDoNotLeakRequestSecrets(t *testing.T) {
	t.Parallel()

	const secret = "raw-api-key-sentinel"
	for _, status := range []int{
		fiber.StatusSeeOther,
		fiber.StatusUnauthorized,
		fiber.StatusTooManyRequests,
		fiber.StatusInternalServerError,
		fiber.StatusServiceUnavailable,
	} {
		status := status
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			t.Parallel()

			var output bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&output, nil))
			app := fiber.New()
			app.Use(NewAccessLogMiddleware(logger).Middleware())
			app.Post("/tools/connect", func(c *fiber.Ctx) error {
				if status == fiber.StatusSeeOther {
					return c.Redirect("/tools/mcp/connect?ticket=opaque", status)
				}
				return c.Status(status).SendString(http.StatusText(status))
			})
			req := httptest.NewRequest(
				fiber.MethodPost,
				"/tools/connect",
				strings.NewReader("api_key="+secret),
			)
			req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationForm)

			res, err := app.Test(req)
			require.NoError(t, err)
			_, err = io.Copy(io.Discard, res.Body)
			require.NoError(t, err)
			require.NoError(t, res.Body.Close())
			require.Equal(t, status, res.StatusCode)
			require.Contains(t, output.String(), `"status":`+strconv.Itoa(status))
			require.NotContains(t, output.String(), secret)
		})
	}
}

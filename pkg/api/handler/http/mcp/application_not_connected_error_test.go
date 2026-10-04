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

package mcp

import (
	"encoding/json"
	"io"
	"net/http/httptest"
	"testing"

	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	"github.com/gofiber/fiber/v2"
)

// A client that reads only the code took this for a consent prompt and handed
// its user the connect link the error never carried. The data says it is not one.
func TestWriteAppError_ApplicationNotConnectedSaysWhoFixesIt(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		shared bool
	}{
		{name: "shared account nobody connected", shared: true},
		{name: "per-user account and nobody named", shared: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			app := fiber.New()
			app.Post("/", func(c *fiber.Ctx) error {
				return writeAppError(c, json.RawMessage(`1`), &appmcp.ApplicationNotConnectedError{
					Provider: "linear", Registry: "Linear", Shared: tc.shared,
				})
			})

			resp, err := app.Test(httptest.NewRequest(fiber.MethodPost, "/", nil))
			if err != nil {
				t.Fatalf("app.Test: %v", err)
			}
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("read body: %v", err)
			}
			var got rpcResponse
			if err := json.Unmarshal(body, &got); err != nil {
				t.Fatalf("decode %s: %v", body, err)
			}
			if got.Error == nil || got.Error.Code != codeConsentRequired {
				t.Fatalf("error = %+v, want code %d", got.Error, codeConsentRequired)
			}
			var data map[string]any
			if err := json.Unmarshal(got.Error.Data, &data); err != nil {
				t.Fatalf("decode data %s: %v", got.Error.Data, err)
			}
			if data["reason"] != reasonApplicationNotConnected || data["provider"] != "linear" ||
				data["registry"] != "Linear" || data["shared"] != tc.shared {
				t.Fatalf("data = %v", data)
			}
			if _, ok := data["connect_url"]; ok {
				t.Fatalf("data carries a connect_url nobody can redeem: %v", data)
			}
		})
	}
}

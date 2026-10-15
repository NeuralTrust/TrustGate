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
	"fmt"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/app/identity/sts"
	"github.com/gofiber/fiber/v2"
)

func TestWriteAppError_IdentityIssuerMismatchHidesTheIdentity(t *testing.T) {
	t.Parallel()
	const detail = "identity 0190-pinned expects https://login.microsoftonline.com/other/v2.0"
	app := fiber.New()
	app.Post("/", func(c *fiber.Ctx) error {
		return writeAppError(c, json.RawMessage(`1`), fmt.Errorf("%w: %s", sts.ErrIdentityIssuerMismatch, detail))
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
	if got.Error == nil || got.Error.Code != codeInvalidRequest {
		t.Fatalf("error = %+v, want code %d", got.Error, codeInvalidRequest)
	}
	if got.Error.Message != sts.ErrIdentityIssuerMismatch.Error() || strings.Contains(string(body), "pinned") {
		t.Fatalf("message = %q leaks the pinned identity", got.Error.Message)
	}
}

func TestWriteAppError_ExchangeIdentityUnavailableIsAClientError(t *testing.T) {
	t.Parallel()
	app := fiber.New()
	app.Post("/", func(c *fiber.Ctx) error {
		return writeAppError(c, json.RawMessage(`1`), fmt.Errorf("%w: identity 0190-pinned lacks client_id/client_secret", sts.ErrExchangeIdentityUnavailable))
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
	if got.Error == nil || got.Error.Code != codeInvalidRequest || strings.Contains(string(body), "pinned") {
		t.Fatalf("error = %+v, want a generic invalid request", got.Error)
	}
}

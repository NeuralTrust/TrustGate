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

package registry

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
)

type linkRecorder struct {
	appregistry.SharedAccountService
	resumeURL string
	calls     int
}

func (r *linkRecorder) Link(_ context.Context, _ ids.GatewayID, _ ids.RegistryID, resumeURL string) (*appregistry.SharedAccountLink, error) {
	r.calls++
	r.resumeURL = resumeURL
	return &appregistry.SharedAccountLink{Ticket: "tk", ConsumerPath: "/store/mcp"}, nil
}

func postConnectLink(t *testing.T, accounts appregistry.SharedAccountService, body string) int {
	t.Helper()
	app := fiber.New()
	app.Post("/v1/gateways/:gateway_id/registries/:id/shared-account/connect-link", NewSharedAccountHandler(accounts).ConnectLink)
	target := "/v1/gateways/" + ids.New[ids.GatewayKind]().String() + "/registries/" + ids.New[ids.RegistryKind]().String() + "/shared-account/connect-link"
	req := httptest.NewRequest("POST", target, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := app.Test(req)
	if err != nil {
		t.Fatalf("route test: %v", err)
	}
	return res.StatusCode
}

// The console names the screen the admin connected from, so the page can send
// them back there; a caller that sends no body still gets its page.
func TestSharedAccountConnectLinkPassesTheResumeURL(t *testing.T) {
	t.Parallel()
	with := &linkRecorder{}
	if status := postConnectLink(t, with, `{"resume_url":" https://app.neuraltrust.ai/v2/team/registry "}`); status != fiber.StatusOK {
		t.Fatalf("status = %d", status)
	}
	if with.resumeURL != "https://app.neuraltrust.ai/v2/team/registry" {
		t.Fatalf("resume url = %q", with.resumeURL)
	}

	without := &linkRecorder{}
	if status := postConnectLink(t, without, ""); status != fiber.StatusOK || without.calls != 1 || without.resumeURL != "" {
		t.Fatalf("no body: status = %d, calls = %d, resume = %q", status, without.calls, without.resumeURL)
	}
}

func TestSharedAccountConnectLinkRefusesABodyItCannotRead(t *testing.T) {
	t.Parallel()
	accounts := &linkRecorder{}
	if status := postConnectLink(t, accounts, `{"resume_url":`); status != fiber.StatusUnprocessableEntity && status != fiber.StatusBadRequest {
		t.Fatalf("status = %d, want a validation error", status)
	}
	if accounts.calls != 0 {
		t.Fatal("no link may be minted from a body that could not be read")
	}
}

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

package oauth

import (
	"errors"
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// A person connecting Gmail saw "The provided client secret is invalid" and
// nothing about whose secret it was. They cannot fix it; the page says who can.
func TestRejectedClientError_SaysAnAdministratorUpdatesTheClient(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	provider := &InvalidClientError{Code: "invalid_client", Description: "The provided client secret is invalid."}

	manual, err := registrydomain.NewMCPRegistry(gw, "Gmail", "", &registrydomain.MCPTarget{
		URL: "https://gmailmcp.googleapis.com/mcp/v1",
		Auth: &registrydomain.MCPAuth{
			Mode: registrydomain.MCPAuthModeForwarded, Provider: "com.google.workspace/gmail", ClientID: "id",
			AuthorizeURL: "https://accounts.google.com/o/oauth2/v2/auth", TokenURL: "https://oauth2.googleapis.com/token",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := rejectedClientError(gw, manual, provider)
	if !errors.Is(got, ErrInvalidClient) {
		t.Fatalf("%v no longer reads as ErrInvalidClient", got)
	}
	text := got.Error()
	if !strings.HasPrefix(text, provider.Error()) || !strings.Contains(text, "an administrator updates its client ID or secret") || strings.Contains(text, "..") {
		t.Fatalf("page text = %q", text)
	}

	dynamic, err := registrydomain.NewMCPRegistry(gw, "Notion", "", &registrydomain.MCPTarget{
		URL:  "https://mcp.notion.com/mcp",
		Auth: &registrydomain.MCPAuth{Mode: registrydomain.MCPAuthModeForwarded, Provider: "notion", Registration: registrydomain.RegistrationAuto},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := rejectedClientError(gw, dynamic, provider); got != error(provider) {
		t.Fatalf("a dynamic client's refusal = %v, want it unchanged", got)
	}
}

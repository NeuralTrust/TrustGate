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

package response

import (
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/common/secret"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

func brightDataRegistry(t *testing.T, url string) *domain.Registry {
	t.Helper()
	reg, err := domain.NewMCPRegistry(ids.New[ids.GatewayKind](), "Bright Data", "", &domain.MCPTarget{
		Code: "com.brightdata/mcp",
		URL:  url,
		URLVariables: []domain.MCPURLVariable{
			{Name: "token", Required: true, Secret: true, In: domain.URLVariableInQuery},
			{Name: "zone", In: domain.URLVariableInQuery},
		},
	})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	return reg
}

// Registry reads are open to READ_ONLY app users: a secret URL variable's value
// must come back masked exactly like an auth secret does.
func TestFromRegistry_MasksSecretURLVariableValues(t *testing.T) {
	t.Parallel()
	reg := brightDataRegistry(t, "https://mcp.brightdata.com/mcp?token=supersecretvalue1234&zone=eu&plain=1")
	got := FromRegistry(reg).MCPTarget.URL

	if strings.Contains(got, "supersecretvalue1234") {
		t.Fatalf("secret URL variable leaked: %s", got)
	}
	want := "https://mcp.brightdata.com/mcp?token=" + secret.Mask("supersecretvalue1234") + "&zone=eu&plain=1"
	if got != want {
		t.Fatalf("URL = %q, want %q", got, want)
	}
	if !secret.IsMasked(strings.TrimPrefix(strings.Split(got, "?")[1], "token=")) {
		t.Fatalf("masked token must be recognisable as masked for the update round-trip: %s", got)
	}
}

func TestFromRegistry_LeavesTemplatePlaceholderAndPlainURLsAlone(t *testing.T) {
	t.Parallel()
	const tmpl = "https://mcp.brightdata.com/mcp?token={token}&zone={zone}"
	if got := FromRegistry(brightDataRegistry(t, tmpl)).MCPTarget.URL; got != tmpl {
		t.Fatalf("template URL rewritten: %q, want %q", got, tmpl)
	}

	fixed, err := domain.NewMCPRegistry(ids.New[ids.GatewayKind](), "Linear", "", &domain.MCPTarget{
		URL: "https://mcp.linear.app/mcp?version=2&token=notdeclared",
	})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	if got := FromRegistry(fixed).MCPTarget.URL; got != fixed.MCPTarget.URL {
		t.Fatalf("URL without secret variables rewritten: %q", got)
	}
}

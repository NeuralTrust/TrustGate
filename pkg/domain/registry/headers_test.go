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
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/common/secret"
)

func TestResolveHeaders(t *testing.T) {
	t.Parallel()
	stored := map[string]string{"X-Api-Key": "header-value-aaaa", "X-Tenant": "acme"}

	tests := []struct {
		name     string
		incoming map[string]string
		want     map[string]string
	}{
		{
			name:     "nil incoming stays nil",
			incoming: nil,
			want:     nil,
		},
		{
			name:     "masked echo keeps stored values",
			incoming: map[string]string{"X-Api-Key": secret.Mask("header-value-aaaa"), "X-Tenant": secret.Mask("acme")},
			want:     stored,
		},
		{
			name:     "header names match case-insensitively",
			incoming: map[string]string{"x-api-key": secret.Mask("header-value-aaaa")},
			want:     map[string]string{"x-api-key": "header-value-aaaa"},
		},
		{
			name:     "an edited masked tail is not taken for the stored value",
			incoming: map[string]string{"X-Api-Key": secret.Mask("header-value-aaaa") + "5"},
			want:     map[string]string{"X-Api-Key": secret.Mask("header-value-aaaa") + "5"},
		},
		{
			name:     "a bare marker does not match a long stored value",
			incoming: map[string]string{"X-Api-Key": secret.Redacted},
			want:     map[string]string{"X-Api-Key": secret.Redacted},
		},
		{
			name:     "new value replaces, new key is added, absent key is dropped",
			incoming: map[string]string{"X-Api-Key": "rotated", "X-Region": "eu"},
			want:     map[string]string{"X-Api-Key": "rotated", "X-Region": "eu"},
		},
		{
			name:     "empty map clears every header",
			incoming: map[string]string{},
			want:     map[string]string{},
		},
		{
			name:     "masked value with nothing stored stays masked",
			incoming: map[string]string{"X-Other": "***abcd"},
			want:     map[string]string{"X-Other": "***abcd"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ResolveHeaders(tt.incoming, stored)
			if (got == nil) != (tt.want == nil) || !maps.Equal(got, tt.want) {
				t.Fatalf("ResolveHeaders = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMCPTarget_ResolveSecretsFromMergesHeadersWithoutAuth(t *testing.T) {
	t.Parallel()
	prev := &MCPTarget{URL: "https://mcp.example.com/mcp", Headers: map[string]string{"X-Api-Key": "header-value-aaaa"}}
	next := &MCPTarget{URL: "https://mcp.example.com/mcp", Headers: map[string]string{"X-Api-Key": secret.Mask("header-value-aaaa")}}
	next.ResolveSecretsFrom(prev)
	if next.Headers["X-Api-Key"] != "header-value-aaaa" {
		t.Fatalf("stored header not kept: %v", next.Headers)
	}
}

func TestMCPTarget_ValidateRefusesMaskedHeader(t *testing.T) {
	t.Parallel()
	target := validMCPTarget()
	target.Headers = map[string]string{"X-Api-Key": "***abcd"}
	if err := target.Validate(); !errors.Is(err, ErrInvalidMCPTarget) {
		t.Fatalf("Validate err = %v, want ErrInvalidMCPTarget", err)
	}
}

func TestHealthChecks_ResolveSecretsFromAndValidate(t *testing.T) {
	t.Parallel()
	prev := &HealthChecks{Interval: 10, Threshold: 3, Headers: map[string]string{"Authorization": "Bearer abcdefgh123"}}
	next := &HealthChecks{Interval: 10, Threshold: 3, Headers: map[string]string{"Authorization": secret.Mask("Bearer abcdefgh123")}}
	next.ResolveSecretsFrom(prev)
	if next.Headers["Authorization"] != "Bearer abcdefgh123" {
		t.Fatalf("stored health check header not kept: %v", next.Headers)
	}
	if err := next.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	orphan := &HealthChecks{Interval: 10, Threshold: 3, Headers: map[string]string{"X-New": "***"}}
	if err := orphan.Validate(); !errors.Is(err, ErrInvalidHealthChecks) {
		t.Fatalf("Validate err = %v, want ErrInvalidHealthChecks", err)
	}
}

func TestMCPAuth_ValidateAllowsUnreadableStoredSecret(t *testing.T) {
	t.Parallel()
	static := &MCPAuth{Mode: MCPAuthModeStatic, Header: "Authorization"}
	if err := static.Validate(); !errors.Is(err, ErrInvalidMCPTarget) {
		t.Fatalf("empty static value must still be refused: %v", err)
	}
	static.SecretUnreadable = true
	if err := static.Validate(); err != nil {
		t.Fatalf("unreadable static value: %v", err)
	}
	cc := &MCPAuth{Mode: MCPAuthModeClientCredentials, ClientID: "cid", TokenURL: "https://idp.example.com/token", SecretUnreadable: true}
	if err := cc.Validate(); err != nil {
		t.Fatalf("unreadable client secret: %v", err)
	}

	next := &MCPTarget{Auth: &MCPAuth{Mode: MCPAuthModeStatic, Header: "Authorization", Value: "***"}}
	next.ResolveSecretsFrom(&MCPTarget{Auth: static})
	if next.Auth.Value != "" || !next.Auth.SecretUnreadable {
		t.Fatalf("marker not carried: %+v", next.Auth)
	}
	fresh := &MCPTarget{Auth: &MCPAuth{Mode: MCPAuthModeStatic, Header: "Authorization", Value: "new"}}
	fresh.ResolveSecretsFrom(&MCPTarget{Auth: static})
	if fresh.Auth.SecretUnreadable {
		t.Fatal("a new value clears the marker")
	}
}

func TestMCPTarget_ValidateRefusesAnEditedMaskedHeader(t *testing.T) {
	t.Parallel()
	prev := &MCPTarget{URL: "https://mcp.example.com/mcp", Headers: map[string]string{"X-Api-Key": "header-value-aaaa"}}
	next := &MCPTarget{URL: "https://mcp.example.com/mcp", Headers: map[string]string{"X-Api-Key": "***aaab"}}
	next.ResolveSecretsFrom(prev)
	err := next.Validate()
	if !errors.Is(err, ErrInvalidMCPTarget) || !strings.Contains(err.Error(), "looks masked") {
		t.Fatalf("Validate err = %v, want the masked-header refusal", err)
	}
}

func TestMCPTarget_ResolveSecretsFromCarriesUnreadableHeaders(t *testing.T) {
	t.Parallel()
	prev := &MCPTarget{
		URL:               "https://mcp.example.com/mcp",
		Headers:           map[string]string{"X-Api-Key": "", "X-Tenant": "acme"},
		UnreadableHeaders: []string{"X-Api-Key"},
	}
	for _, echoed := range []string{"", secret.Redacted, "***abcd"} {
		next := &MCPTarget{URL: prev.URL, Headers: map[string]string{"x-api-key": echoed, "X-Tenant": "acme"}}
		next.ResolveSecretsFrom(prev)
		if next.Headers["x-api-key"] != "" || !slices.Equal(next.UnreadableHeaders, []string{"x-api-key"}) {
			t.Fatalf("echo %q: headers %v, unreadable %v", echoed, next.Headers, next.UnreadableHeaders)
		}
		if err := next.Validate(); err != nil {
			t.Fatalf("echo %q: Validate: %v", echoed, err)
		}
	}
	replaced := &MCPTarget{URL: prev.URL, Headers: map[string]string{"X-Api-Key": "new-value"}}
	replaced.ResolveSecretsFrom(prev)
	if replaced.Headers["X-Api-Key"] != "new-value" || len(replaced.UnreadableHeaders) != 0 {
		t.Fatalf("a new value clears the mark: %v %v", replaced.Headers, replaced.UnreadableHeaders)
	}
}

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
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

func TestMCPTarget_UserHeadersValidate(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		mutate  func(*MCPTarget)
		wantErr string
	}{
		{name: "one api key header with no auth", mutate: func(tg *MCPTarget) {
			tg.Auth = &MCPAuth{Mode: MCPAuthModeNone}
			tg.UserHeaders = []MCPUserHeader{{Name: "X-API-Key", Required: true, Secret: true}}
		}},
		{name: "combined with shared header and static auth on another name", mutate: func(tg *MCPTarget) {
			tg.Headers = map[string]string{"X-Tenant": "acme"}
			tg.UserHeaders = []MCPUserHeader{{Name: "X-API-Key", Secret: true}, {Name: "X-Account", Scheme: "Id"}}
		}},
		{name: "per-user Authorization with no auth mode", mutate: func(tg *MCPTarget) {
			tg.Auth = &MCPAuth{Mode: MCPAuthModeNone}
			tg.UserHeaders = []MCPUserHeader{{Name: "Authorization", Scheme: "Bearer", Secret: true}}
		}},
		{name: "per-user Authorization when static auth sets it", mutate: func(tg *MCPTarget) {
			tg.UserHeaders = []MCPUserHeader{{Name: "authorization"}}
		}, wantErr: "already set by auth mode"},
		{name: "per-user Authorization when forwarded sets it", mutate: func(tg *MCPTarget) {
			tg.Auth = &MCPAuth{Mode: MCPAuthModeForwarded, Provider: "p", Registration: RegistrationAuto}
			tg.UserHeaders = []MCPUserHeader{{Name: "Authorization"}}
		}, wantErr: "already set by auth mode"},
		{name: "static auth on a custom header collides", mutate: func(tg *MCPTarget) {
			tg.Auth = &MCPAuth{Mode: MCPAuthModeStatic, Header: "X-API-Key", Value: "k"}
			tg.UserHeaders = []MCPUserHeader{{Name: "x-api-key"}}
		}, wantErr: "already set by auth mode"},
		{name: "shared and per-user at once", mutate: func(tg *MCPTarget) {
			tg.Headers = map[string]string{"x-api-key": "shared"}
			tg.UserHeaders = []MCPUserHeader{{Name: "X-API-Key"}}
		}, wantErr: "both shared and per-user"},
		{name: "duplicate", mutate: func(tg *MCPTarget) {
			tg.UserHeaders = []MCPUserHeader{{Name: "X-Key"}, {Name: "x-key"}}
		}, wantErr: "declared twice"},
		{name: "reserved host", mutate: func(tg *MCPTarget) {
			tg.UserHeaders = []MCPUserHeader{{Name: "Host"}}
		}, wantErr: "reserved"},
		{name: "reserved session id", mutate: func(tg *MCPTarget) {
			tg.UserHeaders = []MCPUserHeader{{Name: "mcp-session-id"}}
		}, wantErr: "reserved"},
		{name: "reserved gateway namespace", mutate: func(tg *MCPTarget) {
			tg.UserHeaders = []MCPUserHeader{{Name: "X-NeuralTrust-End-User"}}
		}, wantErr: "reserved"},
		{name: "invalid name", mutate: func(tg *MCPTarget) {
			tg.UserHeaders = []MCPUserHeader{{Name: "X Key"}}
		}, wantErr: "not a valid HTTP header name"},
		{name: "empty name", mutate: func(tg *MCPTarget) {
			tg.UserHeaders = []MCPUserHeader{{Name: " "}}
		}, wantErr: "not a valid HTTP header name"},
		{name: "invalid scheme", mutate: func(tg *MCPTarget) {
			tg.UserHeaders = []MCPUserHeader{{Name: "X-Key", Scheme: "Bear er"}}
		}, wantErr: "not a valid token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tg := validMCPTarget()
			tc.mutate(tg)
			err := tg.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil || !errors.Is(err, ErrInvalidMCPTarget) || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Validate() = %v, want ErrInvalidMCPTarget containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestValidateUserHeaderValue(t *testing.T) {
	t.Parallel()
	h := MCPUserHeader{Name: "X-API-Key"}
	cases := []struct {
		name  string
		value string
		ok    bool
	}{
		{"plain key", "sk-live_abc.123", true},
		{"with space", "abc def", true},
		{"empty", "  ", false},
		{"crlf injection", "abc\r\nX-Evil: 1", false},
		{"lf", "abc\nd", false},
		{"nul", "abc\x00", false},
		{"non ascii", "clé", false},
		{"too long", strings.Repeat("a", MaxUserHeaderValueLen+1), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateUserHeaderValue(h, tc.value)
			if tc.ok != (err == nil) {
				t.Fatalf("ValidateUserHeaderValue() = %v, want ok=%v", err, tc.ok)
			}
			if err != nil && strings.Contains(err.Error(), "abc") {
				t.Fatalf("error echoes the value: %v", err)
			}
		})
	}
}

func TestUserHeaderVaultProvider(t *testing.T) {
	t.Parallel()
	pre, pro := ids.New[ids.RegistryKind](), ids.New[ids.RegistryKind]()
	if UserHeaderVaultProvider(pre, "x-api-key") != UserHeaderVaultProvider(pre, " X-API-KEY ") {
		t.Fatal("header case must not change the vault key")
	}
	if UserHeaderVaultProvider(pre, "X-API-Key") == UserHeaderVaultProvider(pro, "X-API-Key") {
		t.Fatal("two instances must not share a value")
	}
	if !strings.HasPrefix(UserHeaderVaultProvider(pre, "X-API-Key"), UserHeaderVaultPrefix(pre)) {
		t.Fatal("per-header key must sit under the registry prefix")
	}
}

func TestMCPUserHeader_FormatValue(t *testing.T) {
	t.Parallel()
	if got := (MCPUserHeader{Scheme: "Bearer"}).FormatValue("tok"); got != "Bearer tok" {
		t.Fatalf("got %q", got)
	}
	if got := (MCPUserHeader{}).FormatValue("tok"); got != "tok" {
		t.Fatalf("got %q", got)
	}
}

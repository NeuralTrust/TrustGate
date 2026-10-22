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

package identity

import (
	"bytes"
	"log/slog"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestHasScopes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		held     []string
		required []string
		want     bool
	}{
		{"no requirements", nil, nil, true},
		{"exact match", []string{"mcp:use"}, []string{"mcp:use"}, true},
		{"missing", []string{"openid"}, []string{"mcp:use"}, false},
		{"entra leaf satisfies resource-qualified requirement", []string{"mcp.access"}, []string{"api://client-id/mcp.access"}, true},
		{"exact resource-qualified match", []string{"api://client-id/mcp.access"}, []string{"api://client-id/mcp.access"}, true},
		{"leaf mismatch", []string{"other.scope"}, []string{"api://client-id/mcp.access"}, false},
		{"trailing slash requirement is not satisfied by empty leaf", []string{""}, []string{"api://client-id/"}, false},
		{"offline_access is request-only, not enforced", []string{"mcp.access"}, []string{"mcp.access", "offline_access"}, true},
		{"protocol scopes alone always pass", nil, []string{"openid", "profile", "email", "offline_access"}, true},
		{"protocol scopes do not mask a missing resource scope", []string{"openid"}, []string{"offline_access", "mcp.access"}, false},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p := &Principal{Scopes: tt.held}
			if got := p.HasScopes(tt.required); got != tt.want {
				t.Fatalf("HasScopes(%v) with %v = %v, want %v", tt.required, tt.held, got, tt.want)
			}
		})
	}
}

func TestPrincipalEmail(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		p    *Principal
		want string
	}{
		{"nil principal", nil, ""},
		{"no claims", &Principal{Subject: "u1"}, ""},
		{"email claim", &Principal{Claims: map[string]any{"email": "ada@example.com", "sub": "1"}}, "ada@example.com"},
		{"emailAddress claim", &Principal{Claims: map[string]any{"emailAddress": "ada@example.com"}}, "ada@example.com"},
		{"preferred_username email", &Principal{Claims: map[string]any{"preferred_username": "ada@example.com"}}, "ada@example.com"},
		{"preferred_username not email", &Principal{Claims: map[string]any{"preferred_username": "ada"}}, ""},
		{"upn", &Principal{Claims: map[string]any{"upn": "ada@contoso.com"}}, "ada@contoso.com"},
		{"whitespace rejected", &Principal{Claims: map[string]any{"email": "ada @example.com"}}, ""},
		{"non-string ignored", &Principal{Claims: map[string]any{"email": 42}}, ""},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.p.Email(); got != tt.want {
				t.Fatalf("Email() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGroupsFromClaim(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		value any
		want  []string
	}{
		{name: "string", value: " eng  sre eng ", want: []string{"eng", "sre"}},
		{name: "string slice", value: []string{" eng ", "", "sre", "eng"}, want: []string{"eng", "sre"}},
		{name: "JSON array", value: []any{" eng ", 42, "sre", "eng"}, want: []string{"eng", "sre"}},
		{name: "unsupported", value: 42},
		{name: "nil"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := GroupsFromClaim(test.value); !reflect.DeepEqual(got, test.want) {
				t.Fatalf("GroupsFromClaim() = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestGroupsFromClaims(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		claims map[string]any
		want   []string
	}{
		{name: "string", claims: map[string]any{ClaimGroups: " eng  sre eng "}, want: []string{"eng", "sre"}},
		{name: "case sensitive", claims: map[string]any{ClaimGroups: "Eng eng"}, want: []string{"Eng", "eng"}},
		{name: "string slice", claims: map[string]any{ClaimGroups: []string{" eng ", "", "sre", "eng"}}, want: []string{"eng", "sre"}},
		{name: "mixed array", claims: map[string]any{ClaimGroups: []any{" eng ", 42, "sre", "eng", map[string]any{"name": "dropped"}}}, want: []string{"eng", "sre"}},
		{name: "object", claims: map[string]any{ClaimGroups: map[string]any{"name": "eng"}}},
		{name: "nil claim", claims: map[string]any{ClaimGroups: nil}},
		{name: "absent", claims: map[string]any{}},
		{name: "nil map"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := GroupsFromClaims(test.claims); !reflect.DeepEqual(got, test.want) {
				t.Fatalf("GroupsFromClaims() = %#v, want %#v", got, test.want)
			}
		})
	}
}

// Not parallel: it replaces slog.Default for the duration of the test.
func TestGroupsFromClaimsDropWarns(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	const group = "eng-secret"
	const email = "ada@example.com"

	got := GroupsFromClaims(map[string]any{ClaimGroups: []any{group, map[string]any{"mail": email}, false}})
	if !reflect.DeepEqual(got, []string{group}) {
		t.Fatalf("GroupsFromClaims() = %#v, want [%q]", got, group)
	}
	assertGroupsDropLog(t, buf.String(), "[]interface {}", 2, group, email)

	buf.Reset()
	if got := GroupsFromClaims(map[string]any{ClaimGroups: map[string]any{"name": group, "mail": email}}); got != nil {
		t.Fatalf("GroupsFromClaims(object) = %#v, want nil", got)
	}
	assertGroupsDropLog(t, buf.String(), "map[string]interface {}", 1, group, email)

	buf.Reset()
	GroupsFromClaims(map[string]any{ClaimGroups: 42})
	GroupsFromClaims(map[string]any{ClaimGroups: 42})
	if strings.Count(buf.String(), `"msg":"identity: groups claim dropped unsupported values"`) != 2 {
		t.Fatalf("each dropped claim logs once, got %s", buf.String())
	}

	buf.Reset()
	if got := GroupsFromClaims(map[string]any{ClaimGroups: " eng  sre "}); !reflect.DeepEqual(got, []string{"eng", "sre"}) {
		t.Fatalf("GroupsFromClaims(string) = %#v", got)
	}
	if got := GroupsFromClaims(map[string]any{ClaimGroups: []string{"eng", "sre"}}); !reflect.DeepEqual(got, []string{"eng", "sre"}) {
		t.Fatalf("GroupsFromClaims(slice) = %#v", got)
	}
	if got := GroupsFromClaims(nil); got != nil {
		t.Fatalf("GroupsFromClaims(nil) = %#v, want nil", got)
	}
	if got := GroupsFromClaims(map[string]any{}); got != nil {
		t.Fatalf("GroupsFromClaims(absent) = %#v, want nil", got)
	}
	if got := GroupsFromClaims(map[string]any{ClaimGroups: nil}); got != nil {
		t.Fatalf("GroupsFromClaims(nil claim) = %#v, want nil", got)
	}
	if buf.Len() != 0 {
		t.Fatalf("supported and absent claims must not warn, got %s", buf.String())
	}
}

func assertGroupsDropLog(t *testing.T, out, typ string, dropped int, absent ...string) {
	t.Helper()
	if !strings.Contains(out, `"level":"WARN"`) || !strings.Contains(out, `"claim":"groups"`) {
		t.Fatalf("expected a warning naming the groups claim, got %s", out)
	}
	if !strings.Contains(out, `"type":"`+typ+`"`) {
		t.Fatalf("type %s missing from %s", typ, out)
	}
	if !strings.Contains(out, `"dropped":`+strconv.Itoa(dropped)) {
		t.Fatalf("dropped %d missing from %s", dropped, out)
	}
	for _, s := range absent {
		if strings.Contains(out, s) {
			t.Fatalf("log contains %q: %s", s, out)
		}
	}
}

func TestPrincipalGroups(t *testing.T) {
	t.Parallel()
	var nilPrincipal *Principal
	if got := nilPrincipal.Groups(); got != nil {
		t.Fatalf("nil principal Groups() = %#v, want nil", got)
	}
	p := &Principal{Claims: map[string]any{ClaimGroups: "platform security"}}
	if got := p.Groups(); !reflect.DeepEqual(got, []string{"platform", "security"}) {
		t.Fatalf("Groups() = %#v", got)
	}
}

func TestPrincipalStoreIdentity(t *testing.T) {
	t.Parallel()
	groups := []string{"engineering", "sre"}
	for name, tc := range map[string]struct {
		p           *Principal
		keyGroup    string
		subject     string
		storeGroups []string
	}{
		"a group key is its group alone": {
			p:        &Principal{Subject: "alice", Method: MethodPersonalKey, Claims: map[string]any{ClaimGroups: groups, ClaimKeyGroup: " sre "}},
			keyGroup: "sre", storeGroups: []string{"sre"},
		},
		"a personal key is its owner": {
			p:       &Principal{Subject: "alice", Method: MethodPersonalKey, Claims: map[string]any{ClaimGroups: groups}},
			subject: "alice", storeGroups: groups,
		},
		"a token cannot claim a key group": {
			p:       &Principal{Subject: "alice", Method: MethodExternalJWT, Claims: map[string]any{ClaimGroups: groups, ClaimKeyGroup: "sre"}},
			subject: "alice", storeGroups: groups,
		},
		"nor can an application key": {
			p:       &Principal{Subject: "ci", Method: MethodAPIKey, Claims: map[string]any{ClaimKeyGroup: "sre"}},
			subject: "ci",
		},
		"nobody": {p: nil},
	} {
		if got := tc.p.KeyGroup(); got != tc.keyGroup {
			t.Fatalf("%s: KeyGroup() = %q, want %q", name, got, tc.keyGroup)
		}
		if got := tc.p.StoreSubject(); got != tc.subject {
			t.Fatalf("%s: StoreSubject() = %q, want %q", name, got, tc.subject)
		}
		if got := tc.p.StoreGroups(); !reflect.DeepEqual(got, tc.storeGroups) && (len(got) != 0 || len(tc.storeGroups) != 0) {
			t.Fatalf("%s: StoreGroups() = %#v, want %#v", name, got, tc.storeGroups)
		}
	}
}

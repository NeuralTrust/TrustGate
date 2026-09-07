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
	"testing"
)

func TestTemplateVariableNames(t *testing.T) {
	got := TemplateVariableNames("https://{account_url}/db/{database}/{database}/{schema}")
	want := []string{"account_url", "database", "schema"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	if TemplateVariableNames("https://mcp.linear.app/mcp") != nil {
		t.Fatal("a fully-determined URL must have no variables")
	}
}

func TestResolveURL_NoVariablesIsPassthrough(t *testing.T) {
	const u = "https://mcp.linear.app/mcp"
	got, err := ResolveURL(u, nil, nil)
	if err != nil || got != u {
		t.Fatalf("passthrough failed: got %q err %v", got, err)
	}
}

func TestResolveURL_Snowflake(t *testing.T) {
	tmpl := "https://{account_url}/api/v2/databases/{database}/schemas/{schema}/mcp-servers/{name}"
	vars := []MCPURLVariable{
		{Name: "account_url", Required: true},
		{Name: "database", Required: true},
		{Name: "schema", Required: true},
		{Name: "name", Required: true},
	}
	got, err := ResolveURL(tmpl, vars, map[string]string{
		"account_url": "xy12345.us-east-1.snowflakecomputing.com",
		"database":    "ANALYTICS",
		"schema":      "PUBLIC",
		"name":        "cortex",
	})
	if err != nil {
		t.Fatalf("ResolveURL: %v", err)
	}
	want := "https://xy12345.us-east-1.snowflakecomputing.com/api/v2/databases/ANALYTICS/schemas/PUBLIC/mcp-servers/cortex"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestResolveURL_HostVariable(t *testing.T) {
	got, err := ResolveURL("https://{instance}.service-now.com/mcp/{server}",
		[]MCPURLVariable{{Name: "instance", Required: true}, {Name: "server", Required: true}},
		map[string]string{"instance": "acme-dev", "server": "cmdb"})
	if err != nil {
		t.Fatalf("ResolveURL: %v", err)
	}
	if got != "https://acme-dev.service-now.com/mcp/cmdb" {
		t.Fatalf("unexpected host substitution: %q", got)
	}
}

func TestResolveURL_QuerySecretIsEscaped(t *testing.T) {
	got, err := ResolveURL("https://mcp.brightdata.com/mcp?token={token}",
		[]MCPURLVariable{{Name: "token", Required: true, Secret: true, In: URLVariableInQuery}},
		map[string]string{"token": "a b/c+d=e"})
	if err != nil {
		t.Fatalf("ResolveURL: %v", err)
	}
	if got != "https://mcp.brightdata.com/mcp?token=a+b%2Fc%2Bd%3De" {
		t.Fatalf("query value not escaped: %q", got)
	}
}

func TestResolveURL_MissingValueFails(t *testing.T) {
	_, err := ResolveURL("https://{instance}.example.com/mcp",
		[]MCPURLVariable{{Name: "instance", Required: true}},
		map[string]string{})
	if !errors.Is(err, ErrURLTemplate) {
		t.Fatalf("missing value must error, got %v", err)
	}
}

func TestResolveURL_RejectsStructureInjection(t *testing.T) {
	// A host variable that tries to inject a new host / path / credentials must be
	// rejected, not substituted — otherwise a user could repoint the upstream.
	for _, bad := range []string{
		"evil.com/",
		"evil.com#",
		"evil.com:9999",
		"user@evil.com",
		"a/../../etc",
		"..",
		"has space",
		"pct%2fescape",
	} {
		_, err := ResolveURL("https://{host}.example.com/mcp",
			[]MCPURLVariable{{Name: "host", Required: true}},
			map[string]string{"host": bad})
		if !errors.Is(err, ErrURLTemplate) {
			t.Fatalf("value %q must be rejected, got err %v", bad, err)
		}
	}
}

func TestValidate_AcceptsHostTemplate(t *testing.T) {
	// A host-placeholder template is not a legal URL until resolved; the target
	// must still validate because the value is filled per-user at dial time.
	for _, tmpl := range []string{
		"https://{instance}.service-now.com/mcp",
		"https://{account_url}/api/v2/databases/{database}/mcp",
		"https://mcp.brightdata.com/mcp?token={token}",
	} {
		tgt := &MCPTarget{
			Source:       MCPSourceRemote,
			URL:          tmpl,
			URLVariables: []MCPURLVariable{{Name: "instance"}, {Name: "account_url"}, {Name: "database"}, {Name: "token"}},
		}
		tgt.Normalize()
		if err := tgt.Validate(); err != nil {
			t.Fatalf("template %q must validate, got %v", tmpl, err)
		}
	}
	// Without a URL-variable declaration, a raw "{" host is still rejected.
	bad := &MCPTarget{Source: MCPSourceRemote, URL: "https://{instance}.example.com/mcp"}
	bad.Normalize()
	if err := bad.Validate(); err == nil {
		t.Fatal("a '{' host with no URL-variable declaration must stay invalid")
	}
}

func TestValidateURLValues(t *testing.T) {
	vars := []MCPURLVariable{
		{Name: "instance", Required: true},
		{Name: "token", Required: true, Secret: true, In: URLVariableInQuery},
		{Name: "optional", Required: false},
	}
	if err := ValidateURLValues(vars, map[string]string{"instance": "acme", "token": "sk-Abc.123="}); err != nil {
		t.Fatalf("valid values rejected: %v", err)
	}
	if err := ValidateURLValues(vars, map[string]string{"token": "x"}); !errors.Is(err, ErrURLTemplate) {
		t.Fatal("missing required 'instance' must error")
	}
	if err := ValidateURLValues(vars, map[string]string{"instance": "acme/../x", "token": "x"}); !errors.Is(err, ErrURLTemplate) {
		t.Fatal("unsafe host segment must error")
	}
	if err := ValidateURLValues(vars, map[string]string{"instance": "acme", "token": "x", "bogus": "y"}); !errors.Is(err, ErrURLTemplate) {
		t.Fatal("unknown variable must error")
	}
}

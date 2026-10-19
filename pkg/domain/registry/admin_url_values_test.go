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

import "testing"

func TestAdminBoundValues_SnowflakeQA(t *testing.T) {
	t.Parallel()
	const template = "https://{account_url}/api/v2/databases/{database}/schemas/{schema}/mcp-servers/{name}"
	const saved = "https://xy12345.us-east-1.snowflakecomputing.com/api/v2/databases/QA_MCP/schemas/PUBLIC/mcp-servers/QA_AGENT"
	vars := []MCPURLVariable{
		{Name: "account_url", Required: true},
		{Name: "database", Required: true},
		{Name: "schema", Required: true},
		{Name: "name", Required: true},
	}
	got, ok := AdminBoundValues(template, vars, saved)
	if !ok {
		t.Fatal("admin URL did not match the catalog template")
	}
	want := map[string]string{
		"account_url": "xy12345.us-east-1.snowflakecomputing.com",
		"database":    "QA_MCP",
		"schema":      "PUBLIC",
		"name":        "QA_AGENT",
	}
	if len(got) != len(want) {
		t.Fatalf("values = %#v", got)
	}
	for name, value := range want {
		if got[name] != value {
			t.Fatalf("%s = %q, want %q", name, got[name], value)
		}
	}
}

func TestAdminBoundValues_PagerDutyRegions(t *testing.T) {
	t.Parallel()
	const template = "https://{host}/mcp"
	vars := []MCPURLVariable{{
		Name:     "host",
		Required: true,
		Options: []MCPURLVariableOption{
			{Value: "mcp.pagerduty.com"},
			{Value: "mcp.eu.pagerduty.com"},
		},
	}}
	us, ok := AdminBoundValues(template, vars, "https://mcp.pagerduty.com/mcp")
	if !ok || us["host"] != "mcp.pagerduty.com" {
		t.Fatalf("us = %#v ok=%v", us, ok)
	}
	eu, ok := AdminBoundValues(template, vars, "https://mcp.eu.pagerduty.com/mcp")
	if !ok || eu["host"] != "mcp.eu.pagerduty.com" {
		t.Fatalf("eu = %#v ok=%v", eu, ok)
	}
}

func TestAdminBoundValues_TemplateCopyIsEmpty(t *testing.T) {
	t.Parallel()
	got, ok := AdminBoundValues("https://{host}/mcp", nil, "https://{host}/mcp")
	if !ok || len(got) != 0 {
		t.Fatalf("template copy = %#v ok=%v", got, ok)
	}
}

func TestAdminBoundValues_OmitsSecret(t *testing.T) {
	t.Parallel()
	got, ok := AdminBoundValues(
		"https://mcp.example.com/mcp?token={token}",
		[]MCPURLVariable{{Name: "token", Secret: true, In: URLVariableInQuery}},
		"https://mcp.example.com/mcp?token=secret-value",
	)
	if !ok || len(got) != 0 {
		t.Fatalf("secret leaked into admin values: %#v ok=%v", got, ok)
	}
}

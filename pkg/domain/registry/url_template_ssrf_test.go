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
)

func TestValidateResolvedUpstreamHost_RejectsNonPublicHosts(t *testing.T) {
	rejected := []string{
		"https://169.254.169.254/latest/meta-data/",
		"http://metadata.google.internal/computeMetadata/v1/",
		"https://metadata/computeMetadata/v1/",
		"http://localhost:8080/mcp",
		"http://LOCALHOST./mcp",
		"https://api.localhost/mcp",
		"https://10.0.0.5/mcp",
		"https://192.168.1.10:9000/mcp",
		"https://[::1]/mcp",
		"https://[fd00::1]/mcp",
		"https://127.1/mcp",
		"https://2130706433/mcp",
		"https://0x7f000001/mcp",
		"https://db.internal/mcp",
		"https://vault.corp.local/mcp",
		"https://api.default.svc/mcp",
		"https://api.default.svc.cluster.local/mcp",
		"https://kubernetes.default/mcp",
		"https://instance-data/latest/",
		"https://intranet/mcp",
		"https://user:pw@api.example.com/mcp",
		"https:///mcp",
	}
	for _, u := range rejected {
		err := ValidateResolvedUpstreamHost(u)
		if err == nil {
			t.Errorf("%s: accepted, want rejection", u)
			continue
		}
		if !errors.Is(err, ErrUnsafeUpstreamHost) || !errors.Is(err, ErrURLTemplate) {
			t.Errorf("%s: err = %v, want ErrUnsafeUpstreamHost wrapping ErrURLTemplate", u, err)
		}
	}
}

func TestValidateResolvedUpstreamHost_AcceptsPublicHostnames(t *testing.T) {
	accepted := []string{
		"https://xy12345.us-east-1.snowflakecomputing.com/api/v2/mcp",
		"https://acme.atlassian.net/mcp",
		"https://mcp.brightdata.com/mcp?token=abc",
		"https://cube.example.com:8443/cubejs-api/mcp",
		"http://mcp.example.com./path",
	}
	for _, u := range accepted {
		if err := ValidateResolvedUpstreamHost(u); err != nil {
			t.Errorf("%s: rejected: %v", u, err)
		}
	}
}

// The full first layer: a per-user host value that passes the segment charset
// (169.254.169.254 and metadata.google.internal both do) is resolved into the
// template and then refused by the host gate.
func TestResolveURL_ThenValidate_RefusesMetadataEndpoints(t *testing.T) {
	tmpl := "https://{account_url}/api/v2/mcp"
	vars := []MCPURLVariable{{Name: "account_url", Required: true}}
	for _, host := range []string{"169.254.169.254", "metadata.google.internal", "localhost", "10.0.0.5"} {
		resolved, err := ResolveURL(tmpl, vars, map[string]string{"account_url": host})
		if err != nil {
			t.Fatalf("%s: ResolveURL should substitute (charset allows it): %v", host, err)
		}
		if err := ValidateResolvedUpstreamHost(resolved); !errors.Is(err, ErrUnsafeUpstreamHost) {
			t.Fatalf("%s: resolved %q accepted (%v), want ErrUnsafeUpstreamHost", host, resolved, err)
		}
	}
	resolved, err := ResolveURL(tmpl, vars, map[string]string{"account_url": "acme.snowflakecomputing.com"})
	if err != nil {
		t.Fatalf("ResolveURL: %v", err)
	}
	if err := ValidateResolvedUpstreamHost(resolved); err != nil {
		t.Fatalf("public hostname rejected: %v", err)
	}
}

func TestValidateURLValue_CapsLength(t *testing.T) {
	long := strings.Repeat("a", maxURLValueLen+1)
	if err := ValidateURLValue(MCPURLVariable{Name: "host"}, long); !errors.Is(err, ErrURLTemplate) {
		t.Fatalf("segment value of %d chars accepted (%v), want ErrURLTemplate", len(long), err)
	}
	if err := ValidateURLValue(MCPURLVariable{Name: "token", In: URLVariableInQuery}, long); !errors.Is(err, ErrURLTemplate) {
		t.Fatalf("query value of %d chars accepted (%v), want ErrURLTemplate", len(long), err)
	}
	if err := ValidateURLValue(MCPURLVariable{Name: "host"}, strings.Repeat("a", maxURLValueLen)); err != nil {
		t.Fatalf("value of exactly %d chars rejected: %v", maxURLValueLen, err)
	}
	if err := ValidateURLValues(
		[]MCPURLVariable{{Name: "token", In: URLVariableInQuery, Required: true}},
		map[string]string{"token": long},
	); !errors.Is(err, ErrURLTemplate) {
		t.Fatalf("ValidateURLValues accepted an over-long value: %v", err)
	}
}

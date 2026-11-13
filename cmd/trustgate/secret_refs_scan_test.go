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

package main

import (
	"bytes"
	"strings"
	"testing"

	appsecretstore "github.com/NeuralTrust/TrustGate/pkg/app/secretstore"
)

func TestReportFindings(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := reportFindings(&out, &errOut, nil); code != scanExitClean || out.Len() != 0 {
		t.Fatalf("clean scan: code %d, stdout %q", code, out.String())
	}

	out.Reset()
	if code := reportFindings(&out, &errOut, []appsecretstore.Finding{{Kind: appsecretstore.FindingEmbedded}}); code != scanExitClean || out.Len() == 0 {
		t.Fatalf("embedded only: code %d, stdout %q; want it printed and the scan clean", code, out.String())
	}

	out.Reset()
	code := reportFindings(&out, &errOut, []appsecretstore.Finding{{
		GatewayID: "gw", Entity: "registry", ID: "r1", Name: "openai prod", Field: "llm_target.auth.api_key.api_key", Kind: appsecretstore.FindingReference,
	}})
	if code != scanExitFound {
		t.Fatalf("code = %d, want %d", code, scanExitFound)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 || lines[1] != "gw\tregistry\tr1\t\"openai prod\"\tllm_target.auth.api_key.api_key\treference" {
		t.Fatalf("stdout = %q", out.String())
	}
}

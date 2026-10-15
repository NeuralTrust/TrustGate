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

package googlemodelarmor

import (
	"net/http"
	"strings"
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
)

func TestBlockBodyExactJSON(t *testing.T) {
	t.Parallel()
	got := string(blockBody("PII detected in the response.", finding{filter: filterSDP, infoTypes: []string{"EMAIL_ADDRESS"}}))
	want := `{"error":{"type":"model_armor_blocked","message":"PII detected in the response.","filter":"sdp","info_types":["EMAIL_ADDRESS"]}}`
	if got != want {
		t.Fatalf("blockBody = %s, want %s", got, want)
	}
}

func TestBlockBodyOmitsEmptyInfoTypes(t *testing.T) {
	t.Parallel()
	got := string(blockBody(appplugins.DefaultBlockMessage, finding{filter: filterCSAM}))
	want := `{"error":{"type":"model_armor_blocked","message":"` + appplugins.DefaultBlockMessage + `","filter":"csam"}}`
	if got != want {
		t.Fatalf("blockBody = %s, want %s", got, want)
	}
}

func TestBlockErrorUsesConfiguredMessage(t *testing.T) {
	t.Parallel()
	f := finding{filter: filterRAI}
	err := blockError("Unsafe content detected.", f)
	if err == nil {
		t.Fatal("blockError returned nil")
		return
	}
	if err.StatusCode != http.StatusForbidden {
		t.Fatalf("StatusCode = %d, want %d", err.StatusCode, http.StatusForbidden)
	}
	if err.Type != typeModelArmorBlocked {
		t.Fatalf("Type = %q, want %q", err.Type, typeModelArmorBlocked)
	}
	if err.Message != "Unsafe content detected." {
		t.Fatalf("Message = %q, want %q", err.Message, "Unsafe content detected.")
	}
	ct := err.Headers["Content-Type"]
	if len(ct) != 1 || ct[0] != "application/json" {
		t.Fatalf("Content-Type header = %v, want [application/json]", ct)
	}
	want := `{"error":{"type":"model_armor_blocked","message":"Unsafe content detected.","filter":"rai"}}`
	if string(err.Body) != want {
		t.Fatalf("Body = %s, want %s", err.Body, want)
	}
}

func TestBlockErrorFallsBackToSharedDefaultWhenMessageEmpty(t *testing.T) {
	t.Parallel()
	f := finding{filter: filterRAI}
	err := blockError("   ", f)
	if err == nil {
		t.Fatal("blockError returned nil")
		return
	}
	if err.Message != appplugins.DefaultBlockMessage {
		t.Fatalf("Message = %q, want %q", err.Message, appplugins.DefaultBlockMessage)
	}
	want := `{"error":{"type":"model_armor_blocked","message":"` + appplugins.DefaultBlockMessage + `","filter":"rai"}}`
	if string(err.Body) != want {
		t.Fatalf("Body = %s, want %s", err.Body, want)
	}
	for _, vendor := range []string{"Bedrock", "AWS", "Azure", "Google", "Model Armor", "OpenAI"} {
		if strings.Contains(err.Message, vendor) {
			t.Fatalf("Message %q must not name the vendor %q", err.Message, vendor)
		}
	}
}

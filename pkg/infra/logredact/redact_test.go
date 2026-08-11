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

package logredact

import (
	"strings"
	"testing"
)

func TestRedactLogString_BearerAndHeaders(t *testing.T) {
	in := "upstream failed: Authorization: Bearer sk-live-secret X-TG-API-Key: tgk_abc123"
	got := RedactLogString(in)
	if strings.Contains(got, "sk-live-secret") || strings.Contains(got, "tgk_abc123") {
		t.Fatalf("secrets leaked: %q", got)
	}
	if !strings.Contains(got, placeholder) {
		t.Fatalf("expected placeholder in %q", got)
	}
}

func TestRedactLogString_JSONInline(t *testing.T) {
	in := `decode failed body={"api_key":"sk-secret","model":"gpt-4o"}`
	got := RedactLogString(in)
	if strings.Contains(got, "sk-secret") {
		t.Fatalf("json credential leaked: %q", got)
	}
}

func TestRedactLogString_PreservesSafeText(t *testing.T) {
	in := "collector not found for gateway_id=abc"
	if got := RedactLogString(in); got != in {
		t.Fatalf("safe text altered: %q", got)
	}
}

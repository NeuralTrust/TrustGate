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

package oauth

import (
	"errors"
	"strings"
	"testing"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
)

func TestNormalizeResumeURLAcceptsWhereAWebAppLives(t *testing.T) {
	t.Parallel()
	for raw, want := range map[string]string{
		"":   "",
		"  ": "",
		" https://app.neuraltrust.ai/v2/team/portal?tab=installed ": "https://app.neuraltrust.ai/v2/team/portal?tab=installed",
		"http://localhost:3000/v2/team/portal":                      "http://localhost:3000/v2/team/portal",
		"http://127.0.0.1:3000/portal":                              "http://127.0.0.1:3000/portal",
		"http://[::1]:3000/portal":                                  "http://[::1]:3000/portal",
	} {
		got, err := NormalizeResumeURL(raw)
		if err != nil || got != want {
			t.Fatalf("NormalizeResumeURL(%q) = %q, %v; want %q", raw, got, err, want)
		}
	}
}

func TestNormalizeResumeURLRefusesAnythingElse(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{
		"javascript:alert(1)",
		"JAVASCRIPT://app.neuraltrust.ai/%0aalert(1)",
		"data:text/html,<script>alert(1)</script>",
		"cursor://anysphere.cursor-mcp/oauth/callback",
		"/v2/team/portal",
		"//evil.example.com/portal",
		"http://app.neuraltrust.ai/portal",
		"https://user:pass@app.neuraltrust.ai/portal",
		"https:app.neuraltrust.ai",
		"https://app.neuraltrust.ai/" + strings.Repeat("a", maxResumeURLLen),
	} {
		if got, err := NormalizeResumeURL(raw); !errors.Is(err, commonerrors.ErrValidation) {
			t.Fatalf("NormalizeResumeURL(%q) = %q, %v; want a validation error", raw, got, err)
		}
	}
}

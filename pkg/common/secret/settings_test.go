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

package secret_test

import (
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/common/secret"
)

func bedrockCredsSettings(accessKey, secretKey, sessionToken string) map[string]any {
	return map[string]any{
		"guardrail_id": "gr-123",
		"credentials": map[string]any{
			"access_key_id":     accessKey,
			"secret_access_key": secretKey,
			"session_token":     sessionToken,
			"use_role":          false,
		},
	}
}

var bedrockPaths = []string{
	"credentials.access_key_id",
	"credentials.secret_access_key",
	"credentials.session_token",
}

func TestMaskSettings_MasksDeclaredPaths(t *testing.T) {
	t.Parallel()
	settings := bedrockCredsSettings("AKIAREALVALUE", "sk-supersecretvalue1234", "")
	out := secret.MaskSettings(settings, bedrockPaths)

	creds := out["credentials"].(map[string]any)
	if got := creds["access_key_id"]; got != secret.Redacted+"ALUE" {
		t.Fatalf("access_key_id = %v, want %q", got, secret.Redacted+"ALUE")
	}
	if got := creds["secret_access_key"]; got != secret.Redacted+"1234" {
		t.Fatalf("secret_access_key = %v, want %q", got, secret.Redacted+"1234")
	}
	if got, ok := creds["session_token"]; !ok || got != "" {
		t.Fatalf("session_token = %v, want empty string left alone (Mask(\"\") == \"\")", got)
	}
	if got := creds["use_role"]; got != false {
		t.Fatalf("use_role = %v, want untouched false", got)
	}
	if got := out["guardrail_id"]; got != "gr-123" {
		t.Fatalf("guardrail_id = %v, want untouched", got)
	}
}

// This is the aliasing bug from RUN-1646: FromPolicy and app/plugins/plan.go
// both read the same *policy.Policy.Settings map. If MaskSettings mutated it,
// every plugin execution after the first response render would receive the
// mask instead of the real credential.
func TestMaskSettings_NeverMutatesTheInputMap(t *testing.T) {
	t.Parallel()
	settings := bedrockCredsSettings("AKIAREALVALUE", "sk-supersecretvalue1234", "sess-token-value")
	creds := settings["credentials"].(map[string]any)

	out := secret.MaskSettings(settings, bedrockPaths)

	if out["credentials"].(map[string]any)["access_key_id"] == creds["access_key_id"] {
		t.Fatal("masked and original share the same credentials map (or value) — mutation leaked")
	}
	if creds["access_key_id"] != "AKIAREALVALUE" {
		t.Fatalf("original access_key_id = %v, want it untouched (AKIAREALVALUE)", creds["access_key_id"])
	}
	if creds["secret_access_key"] != "sk-supersecretvalue1234" {
		t.Fatalf("original secret_access_key = %v, want it untouched", creds["secret_access_key"])
	}
	if creds["session_token"] != "sess-token-value" {
		t.Fatalf("original session_token = %v, want it untouched", creds["session_token"])
	}
	if settings["credentials"].(map[string]any)["access_key_id"] != "AKIAREALVALUE" {
		t.Fatal("settings map itself was mutated through the nested credentials map")
	}
}

func TestMaskSettings_ReturnsSameMapWhenNothingToMask(t *testing.T) {
	t.Parallel()
	settings := map[string]any{"model": "gpt-4"}
	out := secret.MaskSettings(settings, []string{"api_key"})
	settings["model"] = "changed-after"
	if out["model"] != "changed-after" {
		t.Fatal("MaskSettings must return the very same map reference when there is nothing to mask")
	}
}

func TestMaskSettings_TopLevelPath(t *testing.T) {
	t.Parallel()
	settings := map[string]any{"api_key": "sk-supersecretvalue1234", "endpoint": "https://example.com"}
	out := secret.MaskSettings(settings, []string{"api_key"})
	if out["api_key"] != secret.Redacted+"1234" {
		t.Fatalf("api_key = %v, want masked", out["api_key"])
	}
	if settings["api_key"] != "sk-supersecretvalue1234" {
		t.Fatal("original settings mutated")
	}
	if out["endpoint"] != "https://example.com" {
		t.Fatal("sibling key lost")
	}
}

func TestResolveSettings_MaskedIncomingKeepsExisting(t *testing.T) {
	t.Parallel()
	existing := bedrockCredsSettings("AKIAREALVALUE", "sk-supersecretvalue1234", "")
	masked := secret.MaskSettings(existing, bedrockPaths)

	incoming := map[string]any{
		"guardrail_id": "gr-123",
		"credentials": map[string]any{
			"access_key_id":     masked["credentials"].(map[string]any)["access_key_id"],
			"secret_access_key": masked["credentials"].(map[string]any)["secret_access_key"],
			"session_token":     "",
			"use_role":          false,
		},
	}

	secret.ResolveSettings(incoming, existing, bedrockPaths)

	creds := incoming["credentials"].(map[string]any)
	if creds["access_key_id"] != "AKIAREALVALUE" {
		t.Fatalf("access_key_id = %v, want resolved to the stored real value", creds["access_key_id"])
	}
	if creds["secret_access_key"] != "sk-supersecretvalue1234" {
		t.Fatalf("secret_access_key = %v, want resolved to the stored real value", creds["secret_access_key"])
	}
}

func TestResolveSettings_NewValueReplacesStored(t *testing.T) {
	t.Parallel()
	existing := bedrockCredsSettings("AKIAOLDVALUE", "sk-oldsecretvalue1234", "")
	incoming := bedrockCredsSettings("AKIANEWVALUE", "sk-newsecretvalue5678", "")

	secret.ResolveSettings(incoming, existing, bedrockPaths)

	creds := incoming["credentials"].(map[string]any)
	if creds["access_key_id"] != "AKIANEWVALUE" {
		t.Fatalf("access_key_id = %v, want the new value kept", creds["access_key_id"])
	}
	if creds["secret_access_key"] != "sk-newsecretvalue5678" {
		t.Fatalf("secret_access_key = %v, want the new value kept", creds["secret_access_key"])
	}
}

func TestResolveSettings_AbsentPathFillsFromExisting(t *testing.T) {
	t.Parallel()
	existing := bedrockCredsSettings("AKIAREALVALUE", "sk-supersecretvalue1234", "")
	incoming := map[string]any{"guardrail_id": "gr-123"} // no "credentials" key at all

	secret.ResolveSettings(incoming, existing, bedrockPaths)

	creds, ok := incoming["credentials"].(map[string]any)
	if !ok {
		t.Fatalf("credentials not created in incoming, got %#v", incoming)
	}
	if creds["access_key_id"] != "AKIAREALVALUE" || creds["secret_access_key"] != "sk-supersecretvalue1234" {
		t.Fatalf("credentials = %#v, want filled from existing", creds)
	}
}

func TestResolveSettings_MaskedWithNothingStoredIsLeftMasked(t *testing.T) {
	t.Parallel()
	var existing map[string]any // no stored policy at all (create path)
	incoming := map[string]any{
		"credentials": map[string]any{
			"access_key_id": secret.Redacted + "abcd",
		},
	}

	secret.ResolveSettings(incoming, existing, bedrockPaths)

	got := incoming["credentials"].(map[string]any)["access_key_id"]
	if got != secret.Redacted+"abcd" {
		t.Fatalf("access_key_id = %v, want left as the masked literal for RejectMaskedSettings to catch", got)
	}
}

func TestRejectMaskedSettings(t *testing.T) {
	t.Parallel()
	t.Run("rejects a masked leaf", func(t *testing.T) {
		t.Parallel()
		settings := map[string]any{
			"credentials": map[string]any{"access_key_id": secret.Redacted + "abcd"},
		}
		err := secret.RejectMaskedSettings(settings, bedrockPaths)
		if err == nil {
			t.Fatal("want an error for a masked literal with nothing stored")
		}
	})
	t.Run("accepts a real value", func(t *testing.T) {
		t.Parallel()
		settings := bedrockCredsSettings("AKIAREALVALUE", "sk-supersecretvalue1234", "")
		if err := secret.RejectMaskedSettings(settings, bedrockPaths); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("a plugin with no declared paths is unaffected", func(t *testing.T) {
		t.Parallel()
		settings := map[string]any{"anything": secret.Redacted + "zzzz"}
		if err := secret.RejectMaskedSettings(settings, nil); err != nil {
			t.Fatalf("unexpected error with no declared paths: %v", err)
		}
	})
}

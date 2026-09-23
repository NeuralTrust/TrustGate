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
	"errors"
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/common/secret"
)

// fakeEncrypter is a reversible stand-in for the real AES-GCM cipher
// (pkg/infra/crypto), letting these tests exercise EncryptSettings /
// DecryptSettings without depending on the crypto package. The real cipher is
// exercised end-to-end by the policy repository's functional tests.
type fakeEncrypter struct {
	failDecrypt bool
}

func (f fakeEncrypter) Encrypt(plaintext string) (string, error) {
	return "ct:" + plaintext, nil
}

func (f fakeEncrypter) Decrypt(ciphertext string) (string, error) {
	if f.failDecrypt {
		return "", errors.New("fake: decrypt failed")
	}
	if !strings.HasPrefix(ciphertext, "ct:") {
		return "", errors.New("fake: not our ciphertext")
	}
	return strings.TrimPrefix(ciphertext, "ct:"), nil
}

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

func TestEncryptSettings_EncryptsDeclaredPlaintextLeaves(t *testing.T) {
	t.Parallel()
	settings := bedrockCredsSettings("AKIAREALVALUE", "sk-supersecretvalue1234", "")
	out, err := secret.EncryptSettings(settings, bedrockPaths, fakeEncrypter{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	creds := out["credentials"].(map[string]any)
	if got := creds["access_key_id"]; got != secret.EncVersionPrefix+"ct:AKIAREALVALUE" {
		t.Fatalf("access_key_id = %v, want version-prefixed ciphertext", got)
	}
	if got := creds["secret_access_key"]; got != secret.EncVersionPrefix+"ct:sk-supersecretvalue1234" {
		t.Fatalf("secret_access_key = %v, want version-prefixed ciphertext", got)
	}
	// session_token was empty; EncryptSettings must leave it alone same as MaskSettings.
	if got, ok := creds["session_token"]; !ok || got != "" {
		t.Fatalf("session_token = %v, want empty string left alone", got)
	}
	if got := out["guardrail_id"]; got != "gr-123" {
		t.Fatalf("guardrail_id = %v, want untouched", got)
	}
}

func TestEncryptSettings_NeverMutatesTheInputMap(t *testing.T) {
	t.Parallel()
	settings := bedrockCredsSettings("AKIAREALVALUE", "sk-supersecretvalue1234", "sess-token-value")
	_, err := secret.EncryptSettings(settings, bedrockPaths, fakeEncrypter{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	creds := settings["credentials"].(map[string]any)
	if creds["access_key_id"] != "AKIAREALVALUE" {
		t.Fatalf("original access_key_id = %v, want it untouched (the same map is handed to plugin execution)", creds["access_key_id"])
	}
}

func TestEncryptSettings_IsIdempotent(t *testing.T) {
	t.Parallel()
	settings := bedrockCredsSettings("AKIAREALVALUE", "sk-supersecretvalue1234", "")
	once, err := secret.EncryptSettings(settings, bedrockPaths, fakeEncrypter{})
	if err != nil {
		t.Fatalf("first encrypt: %v", err)
	}
	twice, err := secret.EncryptSettings(once, bedrockPaths, fakeEncrypter{})
	if err != nil {
		t.Fatalf("second encrypt: %v", err)
	}
	// A leaf already carrying EncVersionPrefix must not be re-encrypted (that
	// would double-wrap it and make it undecryptable); this is what makes the
	// startup backfill safe to run repeatedly.
	onceCreds := once["credentials"].(map[string]any)
	twiceCreds := twice["credentials"].(map[string]any)
	if onceCreds["access_key_id"] != twiceCreds["access_key_id"] {
		t.Fatalf("re-encrypting a declared path changed it: %v -> %v", onceCreds["access_key_id"], twiceCreds["access_key_id"])
	}
}

func TestDecryptSettings_RoundTrip(t *testing.T) {
	t.Parallel()
	settings := bedrockCredsSettings("AKIAREALVALUE", "sk-supersecretvalue1234", "")
	encrypted, err := secret.EncryptSettings(settings, bedrockPaths, fakeEncrypter{})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	decrypted, err := secret.DecryptSettings(encrypted, bedrockPaths, fakeEncrypter{})
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	creds := decrypted["credentials"].(map[string]any)
	if creds["access_key_id"] != "AKIAREALVALUE" {
		t.Fatalf("access_key_id = %v, want the original plaintext back", creds["access_key_id"])
	}
	if creds["secret_access_key"] != "sk-supersecretvalue1234" {
		t.Fatalf("secret_access_key = %v, want the original plaintext back", creds["secret_access_key"])
	}
}

// This is the non-negotiable tolerant-read requirement: a legacy row written
// before encryption existed carries plain values with no prefix at all, and
// DecryptSettings must pass them through unchanged rather than attempting
// (and failing) to decrypt them.
func TestDecryptSettings_LegacyPlaintextPassesThroughUntouched(t *testing.T) {
	t.Parallel()
	settings := bedrockCredsSettings("AKIALEGACYVALUE", "sk-legacysecretvalue1234", "")
	out, err := secret.DecryptSettings(settings, bedrockPaths, fakeEncrypter{failDecrypt: true})
	if err != nil {
		t.Fatalf("unexpected error decrypting legacy plaintext: %v", err)
	}
	creds := out["credentials"].(map[string]any)
	if creds["access_key_id"] != "AKIALEGACYVALUE" {
		t.Fatalf("access_key_id = %v, want the legacy plaintext untouched", creds["access_key_id"])
	}
	if creds["secret_access_key"] != "sk-legacysecretvalue1234" {
		t.Fatalf("secret_access_key = %v, want the legacy plaintext untouched", creds["secret_access_key"])
	}
}

func TestDecryptSettings_PrefixedButUndecryptableIsAnError(t *testing.T) {
	t.Parallel()
	settings := map[string]any{"api_key": secret.EncVersionPrefix + "garbage"}
	_, err := secret.DecryptSettings(settings, []string{"api_key"}, fakeEncrypter{failDecrypt: true})
	if err == nil {
		t.Fatal("want an error for a version-prefixed value that fails to decrypt")
	}
}

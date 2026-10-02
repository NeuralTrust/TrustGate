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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var bedrockPaths = []string{
	"credentials.access_key_id",
	"credentials.secret_access_key",
	"credentials.session_token",
}

func bedrockSettings() map[string]any {
	return map[string]any{
		"guardrail_id": "gr-1",
		"credentials": map[string]any{
			"aws_region":        "eu-west-1",
			"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
			"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			"session_token":     "",
		},
	}
}

func TestMaskSettings(t *testing.T) {
	t.Parallel()

	t.Run("masks declared paths and keeps the rest", func(t *testing.T) {
		t.Parallel()
		in := bedrockSettings()
		out := secret.MaskSettings(in, bedrockPaths)

		creds := out["credentials"].(map[string]any)
		assert.Equal(t, "***MPLE", creds["access_key_id"])
		assert.Equal(t, "***EKEY", creds["secret_access_key"])
		assert.NotContains(t, creds["secret_access_key"], "wJalr")
		assert.Equal(t, "", creds["session_token"], "an unset credential stays unset")
		assert.Equal(t, "eu-west-1", creds["aws_region"])
		assert.Equal(t, "gr-1", out["guardrail_id"])
	})

	t.Run("never mutates the stored settings", func(t *testing.T) {
		t.Parallel()
		in := bedrockSettings()
		_ = secret.MaskSettings(in, bedrockPaths)
		assert.Equal(t, bedrockSettings(), in, "plugin execution reads this same map and needs the real value")
	})

	t.Run("returns the same map when nothing to mask", func(t *testing.T) {
		t.Parallel()
		in := map[string]any{"guardrail_id": "gr-1"}
		out := secret.MaskSettings(in, bedrockPaths)
		assert.Equal(t, in, out)
	})

	t.Run("non-string value at a declared path is never returned", func(t *testing.T) {
		t.Parallel()
		for name, v := range map[string]any{
			"number": float64(12345678),
			"bool":   true,
			"object": map[string]any{"k": "leakme"},
			"array":  []any{"leakme"},
		} {
			out := secret.MaskSettings(map[string]any{"api_key": v}, []string{"api_key"})
			assert.Equal(t, secret.Redacted, out["api_key"], name)
		}
	})

	t.Run("a non-object where an object is expected is withheld", func(t *testing.T) {
		t.Parallel()
		out := secret.MaskSettings(map[string]any{"credentials": "AKIAleak"}, bedrockPaths)
		assert.Equal(t, secret.Redacted, out["credentials"])
	})

	t.Run("null stays null", func(t *testing.T) {
		t.Parallel()
		out := secret.MaskSettings(map[string]any{"api_key": nil}, []string{"api_key"})
		assert.Nil(t, out["api_key"])
	})
}

func TestWithholdSettings(t *testing.T) {
	t.Parallel()
	in := map[string]any{
		"url":    "https://x",
		"nested": map[string]any{"token": "s3cret", "n": float64(42), "empty": ""},
		"list":   []any{"a", map[string]any{"k": "v"}},
		"none":   nil,
	}
	out := secret.WithholdSettings(in)

	assert.Equal(t, map[string]any{
		"url":    secret.Redacted,
		"nested": map[string]any{"token": secret.Redacted, "n": secret.Redacted, "empty": ""},
		"list":   []any{secret.Redacted, map[string]any{"k": secret.Redacted}},
		"none":   nil,
	}, out)
	assert.Equal(t, "s3cret", in["nested"].(map[string]any)["token"], "input is not mutated")
	assert.Nil(t, secret.WithholdSettings(nil))
}

func TestResolveSettings(t *testing.T) {
	t.Parallel()
	paths := []string{"credentials.session_token", "credentials.secret_access_key"}
	stored := map[string]any{"credentials": map[string]any{
		"secret_access_key": "real-secret-0123456789",
		"session_token":     "tok", // short: its mask is the bare "***"
	}}
	creds := func(m map[string]any) map[string]any { return m["credentials"].(map[string]any) }

	t.Run("exact mask of the stored value keeps it", func(t *testing.T) {
		t.Parallel()
		in := map[string]any{"credentials": map[string]any{
			"secret_access_key": secret.Mask("real-secret-0123456789"),
			"session_token":     secret.Mask("tok"),
		}}
		require.NoError(t, secret.ResolveSettings(in, stored, paths, nil))
		assert.Equal(t, "real-secret-0123456789", creds(in)["secret_access_key"])
		assert.Equal(t, "tok", creds(in)["session_token"])
	})

	t.Run("a mask of some other value is left for validation to reject", func(t *testing.T) {
		t.Parallel()
		in := map[string]any{"credentials": map[string]any{"secret_access_key": "***zzzz"}}
		require.NoError(t, secret.ResolveSettings(in, stored, paths, nil))
		assert.Equal(t, "***zzzz", creds(in)["secret_access_key"])
		require.Error(t, secret.ValidateCredentialSettings(in, paths))
	})

	t.Run("a mask with nothing stored is left for validation to reject", func(t *testing.T) {
		t.Parallel()
		in := map[string]any{"credentials": map[string]any{"session_token": "***"}}
		require.NoError(t, secret.ResolveSettings(in, map[string]any{}, paths, nil))
		assert.Equal(t, "***", creds(in)["session_token"])
	})

	t.Run("omitted and empty are cleared, not merged", func(t *testing.T) {
		t.Parallel()
		in := map[string]any{"credentials": map[string]any{"secret_access_key": ""}}
		require.NoError(t, secret.ResolveSettings(in, stored, paths, nil))
		assert.Equal(t, "", creds(in)["secret_access_key"])
		assert.NotContains(t, creds(in), "session_token")

		bare := map[string]any{"guardrail_id": "x"}
		require.NoError(t, secret.ResolveSettings(bare, stored, paths, nil))
		assert.NotContains(t, bare, "credentials")
	})

	t.Run("a new value replaces", func(t *testing.T) {
		t.Parallel()
		in := map[string]any{"credentials": map[string]any{"secret_access_key": "fresh"}}
		require.NoError(t, secret.ResolveSettings(in, stored, paths, nil))
		assert.Equal(t, "fresh", creds(in)["secret_access_key"])
	})

	t.Run("explicit null is removed", func(t *testing.T) {
		t.Parallel()
		in := map[string]any{"credentials": map[string]any{"session_token": nil}}
		require.NoError(t, secret.ResolveSettings(in, stored, paths, nil))
		assert.NotContains(t, creds(in), "session_token")
	})

	t.Run("a non-string is left for validation, not overwritten", func(t *testing.T) {
		t.Parallel()
		in := map[string]any{"credentials": map[string]any{"secret_access_key": float64(1)}}
		require.NoError(t, secret.ResolveSettings(in, stored, paths, nil))
		assert.Equal(t, float64(1), creds(in)["secret_access_key"])
	})

	t.Run("does not mutate the stored settings", func(t *testing.T) {
		t.Parallel()
		in := map[string]any{"credentials": map[string]any{"session_token": nil, "secret_access_key": secret.Mask("real-secret-0123456789")}}
		require.NoError(t, secret.ResolveSettings(in, stored, paths, nil))
		assert.Equal(t, "tok", creds(stored)["session_token"])
	})
}

func TestValidateCredentialSettings(t *testing.T) {
	t.Parallel()
	paths := []string{"credentials.secret_access_key"}
	tests := []struct {
		name     string
		settings map[string]any
		wantErr  string
	}{
		{name: "absent", settings: map[string]any{}},
		{name: "null", settings: map[string]any{"credentials": map[string]any{"secret_access_key": nil}}},
		{name: "empty", settings: map[string]any{"credentials": map[string]any{"secret_access_key": ""}}},
		{name: "real", settings: map[string]any{"credentials": map[string]any{"secret_access_key": "abc"}}},
		{name: "masked", settings: map[string]any{"credentials": map[string]any{"secret_access_key": "***abcd"}}, wantErr: "masked"},
		{name: "number", settings: map[string]any{"credentials": map[string]any{"secret_access_key": float64(1)}}, wantErr: "must be a string"},
		{name: "object", settings: map[string]any{"credentials": map[string]any{"secret_access_key": map[string]any{}}}, wantErr: "must be a string"},
		{name: "parent not an object", settings: map[string]any{"credentials": "x"}, wantErr: "must be an object"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := secret.ValidateCredentialSettings(tt.settings, paths)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestHasCredentials(t *testing.T) {
	t.Parallel()
	assert.True(t, secret.HasCredentials(map[string]any{"credentials": map[string]any{"access_key_id": "AKIA"}}, bedrockPaths))
	assert.True(t, secret.HasCredentials(map[string]any{"credentials": map[string]any{"access_key_id": float64(1)}}, bedrockPaths))
	assert.False(t, secret.HasCredentials(map[string]any{"credentials": map[string]any{"access_key_id": "", "session_token": nil}}, bedrockPaths))
	assert.False(t, secret.HasCredentials(map[string]any{"guardrail_id": "x"}, bedrockPaths))
	assert.False(t, secret.HasCredentials(nil, bedrockPaths))
}

func TestValidateCredentialSettings_RejectsCaseVariantKeys(t *testing.T) {
	t.Parallel()
	for name, settings := range map[string]map[string]any{
		"leaf":   {"credentials": map[string]any{"SECRET_ACCESS_KEY": "abc"}},
		"parent": {"Credentials": map[string]any{"secret_access_key": "abc"}},
		"mask":   {"credentials": map[string]any{"Secret_Access_Key": "***abcd"}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := secret.ValidateCredentialSettings(settings, []string{"credentials.secret_access_key"})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "settings.credentials.secret_access_key")
			assert.NotContains(t, err.Error(), "abc")
		})
	}
}

// A case-variant key already in storage (written before the write-side check)
// is still the credential to the plugin's decoder, so a read must mask it.
func TestMaskSettings_MasksCaseVariantKeys(t *testing.T) {
	t.Parallel()
	in := map[string]any{"Credentials": map[string]any{"ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE"}, "API_KEY": "sk-live-0123456789"}
	out := secret.MaskSettings(in, []string{"credentials.access_key_id", "api_key"})
	assert.Equal(t, "***MPLE", out["Credentials"].(map[string]any)["ACCESS_KEY_ID"])
	assert.Equal(t, "***6789", out["API_KEY"])
	assert.Equal(t, "sk-live-0123456789", in["API_KEY"], "input is not mutated")
}

func TestResolveSettings_MaskedCredentialIsBoundToItsDestinations(t *testing.T) {
	t.Parallel()
	paths, dests := []string{"api_key"}, []string{"endpoint", "project"}
	stored := map[string]any{"api_key": "REAL-key-0123456789", "endpoint": "https://a.example", "project": "p"}
	mask := secret.Mask("REAL-key-0123456789")

	t.Run("unchanged destinations keep the credential", func(t *testing.T) {
		t.Parallel()
		in := map[string]any{"api_key": mask, "endpoint": "https://a.example", "project": "p"}
		require.NoError(t, secret.ResolveSettings(in, stored, paths, dests))
		assert.Equal(t, "REAL-key-0123456789", in["api_key"])
	})
	for name, in := range map[string]map[string]any{
		"changed endpoint": {"api_key": mask, "endpoint": "https://attacker.example", "project": "p"},
		"changed project":  {"api_key": mask, "endpoint": "https://a.example", "project": "other"},
		"removed endpoint": {"api_key": mask, "project": "p"},
		"added nesting":    {"api_key": mask, "endpoint": map[string]any{"x": 1}, "project": "p"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := secret.ResolveSettings(in, stored, paths, dests)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "settings.api_key")
			assert.Contains(t, err.Error(), "re-enter the credential")
			assert.NotContains(t, err.Error(), "REAL")
			assert.Equal(t, mask, in["api_key"], "the stored credential must not be merged in")
		})
	}
	t.Run("a new credential may move the destination", func(t *testing.T) {
		t.Parallel()
		in := map[string]any{"api_key": "fresh", "endpoint": "https://b.example", "project": "p"}
		require.NoError(t, secret.ResolveSettings(in, stored, paths, dests))
		assert.Equal(t, "fresh", in["api_key"])
	})
}

func TestRejectCaseVariants(t *testing.T) {
	t.Parallel()
	require.Error(t, secret.RejectCaseVariants(map[string]any{"Endpoint": "x"}, []string{"endpoint"}))
	require.NoError(t, secret.RejectCaseVariants(map[string]any{"endpoint": "x"}, []string{"endpoint"}))
}

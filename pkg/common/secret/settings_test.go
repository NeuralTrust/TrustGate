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
		"secret_access_key": "real-secret",
		"session_token":     "real-token",
	}}
	creds := func(m map[string]any) map[string]any { return m["credentials"].(map[string]any) }

	t.Run("masked value keeps stored", func(t *testing.T) {
		t.Parallel()
		in := map[string]any{"credentials": map[string]any{"secret_access_key": "***cret", "session_token": "***"}}
		secret.ResolveSettings(in, stored, paths)
		assert.Equal(t, "real-secret", creds(in)["secret_access_key"])
		assert.Equal(t, "real-token", creds(in)["session_token"])
	})

	t.Run("omitted and empty keep stored, including a missing parent object", func(t *testing.T) {
		t.Parallel()
		in := map[string]any{"credentials": map[string]any{"secret_access_key": ""}}
		secret.ResolveSettings(in, stored, paths)
		assert.Equal(t, "real-secret", creds(in)["secret_access_key"])
		assert.Equal(t, "real-token", creds(in)["session_token"])

		bare := map[string]any{"guardrail_id": "x"}
		secret.ResolveSettings(bare, stored, paths)
		assert.Equal(t, "real-token", creds(bare)["session_token"])
	})

	t.Run("a new value replaces", func(t *testing.T) {
		t.Parallel()
		in := map[string]any{"credentials": map[string]any{"secret_access_key": "fresh"}}
		secret.ResolveSettings(in, stored, paths)
		assert.Equal(t, "fresh", creds(in)["secret_access_key"])
	})

	t.Run("explicit null clears and is not merged back", func(t *testing.T) {
		t.Parallel()
		in := map[string]any{"credentials": map[string]any{"session_token": nil, "secret_access_key": "***cret"}}
		secret.ResolveSettings(in, stored, paths)
		assert.NotContains(t, creds(in), "session_token")
		assert.Equal(t, "real-secret", creds(in)["secret_access_key"])
	})

	t.Run("a non-string is left for validation, not overwritten", func(t *testing.T) {
		t.Parallel()
		in := map[string]any{"credentials": map[string]any{"secret_access_key": float64(1)}}
		secret.ResolveSettings(in, stored, paths)
		assert.Equal(t, float64(1), creds(in)["secret_access_key"])
	})

	t.Run("does not mutate the stored settings", func(t *testing.T) {
		t.Parallel()
		in := map[string]any{"credentials": map[string]any{"session_token": nil}}
		secret.ResolveSettings(in, stored, paths)
		assert.Equal(t, "real-token", creds(stored)["session_token"])
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

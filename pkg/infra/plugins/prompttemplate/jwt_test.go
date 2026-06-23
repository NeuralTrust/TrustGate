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

package prompttemplate

import (
	"testing"

	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func signToken(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte("test-secret"))
	require.NoError(t, err)
	return signed
}

func requestWithHeaders(headers map[string][]string) *infracontext.RequestContext {
	return &infracontext.RequestContext{Headers: headers}
}

func TestBearerToken(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string][]string
		want    string
	}{
		{
			name:    "bearer token extracted",
			headers: map[string][]string{"Authorization": {"Bearer abc.def.ghi"}},
			want:    "abc.def.ghi",
		},
		{
			name:    "bearer token trimmed",
			headers: map[string][]string{"Authorization": {"Bearer   spaced  "}},
			want:    "spaced",
		},
		{
			name:    "case insensitive header",
			headers: map[string][]string{"authorization": {"Bearer token123"}},
			want:    "token123",
		},
		{
			name:    "case insensitive scheme",
			headers: map[string][]string{"Authorization": {"bearer token123"}},
			want:    "token123",
		},
		{
			name:    "non-bearer scheme returns empty",
			headers: map[string][]string{"Authorization": {"Basic dXNlcjpwYXNz"}},
			want:    "",
		},
		{
			name:    "absent header returns empty",
			headers: map[string][]string{},
			want:    "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, bearerToken(requestWithHeaders(tt.headers)))
		})
	}
}

func TestUnverifiedClaim(t *testing.T) {
	valid := signToken(t, jwt.MapClaims{"role": "admin", "tier": 3, "ratio": 1.5})
	tampered := valid[:len(valid)-3] + "AAA"

	t.Run("reads string claim from valid token", func(t *testing.T) {
		value, ok := unverifiedClaim(valid, "role")
		require.True(t, ok)
		assert.Equal(t, "admin", value)
	})

	t.Run("reads numeric claim as string", func(t *testing.T) {
		value, ok := unverifiedClaim(valid, "tier")
		require.True(t, ok)
		assert.Equal(t, "3", value)
	})

	t.Run("reads float claim as string", func(t *testing.T) {
		value, ok := unverifiedClaim(valid, "ratio")
		require.True(t, ok)
		assert.Equal(t, "1.5", value)
	})

	t.Run("tampered token still readable unverified", func(t *testing.T) {
		value, ok := unverifiedClaim(tampered, "role")
		require.True(t, ok)
		assert.Equal(t, "admin", value)
	})

	t.Run("absent claim returns missing", func(t *testing.T) {
		_, ok := unverifiedClaim(valid, "missing")
		assert.False(t, ok)
	})

	t.Run("garbage token returns missing", func(t *testing.T) {
		_, ok := unverifiedClaim("not-a-jwt", "role")
		assert.False(t, ok)
	})

	t.Run("empty token returns missing", func(t *testing.T) {
		_, ok := unverifiedClaim("", "role")
		assert.False(t, ok)
	})
}

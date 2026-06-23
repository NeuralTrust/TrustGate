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

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestResolveContextVars(t *testing.T) {
	token := signToken(t, jwt.MapClaims{"role": "admin"})

	t.Run("header and jwt_claim resolve", func(t *testing.T) {
		cfg := &config{ContextVariables: map[string]contextVar{
			"tenant":    {Source: sourceHeader, Name: "X-Tenant-Id"},
			"user_role": {Source: sourceJWTClaim, Name: "role"},
		}}
		req := requestWithHeaders(map[string][]string{
			"X-Tenant-Id":   {"acme"},
			"Authorization": {"Bearer " + token},
		})
		resolved, missing := resolveContextVars(cfg, req)
		assert.Equal(t, map[string]string{"tenant": "acme", "user_role": "admin"}, resolved)
		assert.Empty(t, missing)
	})

	t.Run("header matched case insensitively", func(t *testing.T) {
		cfg := &config{ContextVariables: map[string]contextVar{
			"tenant": {Source: sourceHeader, Name: "x-tenant-id"},
		}}
		req := requestWithHeaders(map[string][]string{"X-Tenant-Id": {"acme"}})
		resolved, missing := resolveContextVars(cfg, req)
		assert.Equal(t, "acme", resolved["tenant"])
		assert.Empty(t, missing)
	})

	t.Run("absent header reported missing", func(t *testing.T) {
		cfg := &config{ContextVariables: map[string]contextVar{
			"tenant": {Source: sourceHeader, Name: "X-Tenant-Id"},
		}}
		resolved, missing := resolveContextVars(cfg, requestWithHeaders(nil))
		assert.NotContains(t, resolved, "tenant")
		assert.Equal(t, []string{"tenant"}, missing)
	})

	t.Run("absent claim reported missing", func(t *testing.T) {
		cfg := &config{ContextVariables: map[string]contextVar{
			"user_role": {Source: sourceJWTClaim, Name: "role"},
		}}
		req := requestWithHeaders(map[string][]string{"Authorization": {"Bearer " + signToken(t, jwt.MapClaims{"sub": "x"})}})
		resolved, missing := resolveContextVars(cfg, req)
		assert.NotContains(t, resolved, "user_role")
		assert.Equal(t, []string{"user_role"}, missing)
	})

	t.Run("missing token reported missing", func(t *testing.T) {
		cfg := &config{ContextVariables: map[string]contextVar{
			"user_role": {Source: sourceJWTClaim, Name: "role"},
		}}
		resolved, missing := resolveContextVars(cfg, requestWithHeaders(nil))
		assert.Empty(t, resolved)
		assert.Equal(t, []string{"user_role"}, missing)
	})

	t.Run("mixed resolution with missing sorted", func(t *testing.T) {
		cfg := &config{ContextVariables: map[string]contextVar{
			"tenant":    {Source: sourceHeader, Name: "X-Tenant-Id"},
			"region":    {Source: sourceHeader, Name: "X-Region"},
			"user_role": {Source: sourceJWTClaim, Name: "role"},
		}}
		req := requestWithHeaders(map[string][]string{"X-Tenant-Id": {"acme"}})
		resolved, missing := resolveContextVars(cfg, req)
		assert.Equal(t, map[string]string{"tenant": "acme"}, resolved)
		assert.Equal(t, []string{"region", "user_role"}, missing)
	})
}

func TestResolveOneUnknownSource(t *testing.T) {
	value, ok := resolveOne(contextVar{Source: "query", Name: "x"}, requestWithHeaders(nil))
	assert.False(t, ok)
	assert.Empty(t, value)
}

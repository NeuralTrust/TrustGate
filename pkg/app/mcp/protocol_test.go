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

package mcp

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRPCError_ResolvedHTTPStatus(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		err  *RPCError
		want int
	}{
		{name: "nil", err: nil, want: http.StatusBadGateway},
		{name: "explicit", err: &RPCError{HTTPStatus: 403, Code: codePolicyBlocked}, want: 403},
		{name: "policy default", err: &RPCError{Code: codePolicyBlocked}, want: http.StatusForbidden},
		{name: "rate limited", err: &RPCError{Code: CodeRateLimited}, want: http.StatusTooManyRequests},
		{name: "unavailable", err: &RPCError{Code: CodeUnavailable}, want: http.StatusServiceUnavailable},
		{name: "other", err: &RPCError{Code: -32603}, want: http.StatusBadGateway},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, tt.err.ResolvedHTTPStatus())
		})
	}
}

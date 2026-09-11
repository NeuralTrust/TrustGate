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

package middleware

import (
	"strings"
	"testing"
)

func TestForbiddenMessage(t *testing.T) {
	t.Parallel()
	tests := []struct {
		reason string
		want   string
	}{
		{reason: "missing scope consumers:write", want: "Missing required scope consumers:write"},
		{reason: "credential is bound to another gateway", want: "bound to a different gateway"},
		{reason: "credential cannot manage the gateway collection", want: "cannot list or create gateways"},
		{reason: "credential cannot delete a gateway", want: "cannot delete gateways"},
		{reason: "credential is limited to its gateway", want: "limited to its bound gateway"},
		{reason: "something else", want: "Not allowed for this gateway"},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.reason, func(t *testing.T) {
			t.Parallel()
			got := forbiddenMessage(tc.reason)
			if !strings.Contains(got, tc.want) {
				t.Fatalf("forbiddenMessage(%q) = %q, want substring %q", tc.reason, got, tc.want)
			}
		})
	}
}
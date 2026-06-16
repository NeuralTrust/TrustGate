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

package context

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRequestContext_HeaderValue(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string][]string
		lookup  string
		want    string
	}{
		{name: "present", headers: map[string][]string{"X-User-Id": {"u1"}}, lookup: "X-User-Id", want: "u1"},
		{name: "case-insensitive", headers: map[string][]string{"x-user-id": {"u1"}}, lookup: "X-User-Id", want: "u1"},
		{name: "absent", headers: map[string][]string{"X-Other": {"v"}}, lookup: "X-User-Id", want: ""},
		{name: "empty value is treated as absent", headers: map[string][]string{"X-User-Id": {""}}, lookup: "X-User-Id", want: ""},
		{name: "no values is treated as absent", headers: map[string][]string{"X-User-Id": {}}, lookup: "X-User-Id", want: ""},
		{name: "empty lookup", headers: map[string][]string{"X-User-Id": {"u1"}}, lookup: "", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &RequestContext{Headers: tt.headers}
			assert.Equal(t, tt.want, r.HeaderValue(tt.lookup))
		})
	}
}

func TestRequestContext_HeaderValue_NilReceiver(t *testing.T) {
	var r *RequestContext
	assert.Equal(t, "", r.HeaderValue("X-User-Id"))
}

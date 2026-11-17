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

package requestmeta

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClientTraceID(t *testing.T) {
	t.Parallel()

	const traceID = "4bf92f3577b34da6a3ce929d0e0e4736"
	valid := "00-" + traceID + "-00f067aa0ba902b7-01"

	tests := []struct {
		name   string
		values []string
		want   string
	}{
		{name: "valid version 00", values: []string{valid}, want: traceID},
		{name: "unsampled flags", values: []string{"00-" + traceID + "-00f067aa0ba902b7-00"}, want: traceID},
		{name: "future version with extra field", values: []string{"cc-" + traceID + "-00f067aa0ba902b7-01-what-the-future-holds"}, want: traceID},
		{name: "future version exact length", values: []string{"01-" + traceID + "-00f067aa0ba902b7-09"}, want: traceID},
		{name: "absent", values: nil, want: ""},
		{name: "empty", values: []string{""}, want: ""},
		{name: "repeated header", values: []string{valid, valid}, want: ""},
		{name: "version ff", values: []string{"ff-" + traceID + "-00f067aa0ba902b7-01"}, want: ""},
		{name: "version 00 with trailing data", values: []string{valid + "-extra"}, want: ""},
		{name: "future version without dash after flags", values: []string{"01-" + traceID + "-00f067aa0ba902b7-01x"}, want: ""},
		{name: "uppercase trace id", values: []string{"00-" + strings.ToUpper(traceID) + "-00f067aa0ba902b7-01"}, want: ""},
		{name: "uppercase version", values: []string{"0A-" + traceID + "-00f067aa0ba902b7-01"}, want: ""},
		{name: "all-zero trace id", values: []string{"00-00000000000000000000000000000000-00f067aa0ba902b7-01"}, want: ""},
		{name: "all-zero parent id", values: []string{"00-" + traceID + "-0000000000000000-01"}, want: ""},
		{name: "short trace id", values: []string{"00-4bf92f3577b34da6a3ce929d0e0e473-00f067aa0ba902b7-01"}, want: ""},
		{name: "non-hex flags", values: []string{"00-" + traceID + "-00f067aa0ba902b7-0g"}, want: ""},
		{name: "wrong separator", values: []string{"00_" + traceID + "-00f067aa0ba902b7-01"}, want: ""},
		{name: "surrounding spaces", values: []string{" " + valid}, want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, ClientTraceID(tt.values))
		})
	}
}

func TestMCPSessionID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		values []string
		want   string
	}{
		{name: "uuid", values: []string{"1868a90c-6c1b-4e1a-9b3f-0c2d2b0c7e11"}, want: "1868a90c-6c1b-4e1a-9b3f-0c2d2b0c7e11"},
		{name: "visible ascii", values: []string{"a!~Z"}, want: "a!~Z"},
		{name: "max length", values: []string{strings.Repeat("a", 256)}, want: strings.Repeat("a", 256)},
		{name: "absent", values: nil, want: ""},
		{name: "empty", values: []string{""}, want: ""},
		{name: "repeated header", values: []string{"a", "b"}, want: ""},
		{name: "too long", values: []string{strings.Repeat("a", 257)}, want: ""},
		{name: "space", values: []string{"a b"}, want: ""},
		{name: "control character", values: []string{"a\tb"}, want: ""},
		{name: "non-ascii", values: []string{"sesión"}, want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, MCPSessionID(tt.values))
		})
	}
}

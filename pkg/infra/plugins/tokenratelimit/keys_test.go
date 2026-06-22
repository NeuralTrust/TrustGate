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

package tokenratelimit

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAggregateKey(t *testing.T) {
	tests := []struct {
		name        string
		cfgID       string
		dimension   string
		subject     string
		headerValue string
		want        string
	}{
		{
			name:      "global no header",
			cfgID:     "cfg-1",
			dimension: "global",
			subject:   "gw-1",
			want:      "trl:cfg-1:global:gw-1",
		},
		{
			name:      "consumer no header",
			cfgID:     "cfg-1",
			dimension: "consumer",
			subject:   "co-9",
			want:      "trl:cfg-1:consumer:co-9",
		},
		{
			name:        "with header value",
			cfgID:       "cfg-2",
			dimension:   "consumer",
			subject:     "co-9",
			headerValue: "user-1",
			want:        "trl:cfg-2:consumer:co-9:hdr:user-1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := aggregateKey(tt.cfgID, tt.dimension, tt.subject, tt.headerValue)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestModelKey(t *testing.T) {
	base := aggregateKey("cfg-1", "consumer", "co-9", "user-1")
	assert.Equal(t, "trl:cfg-1:consumer:co-9:hdr:user-1:model:gpt-5", modelKey(base, "gpt-5"))
	assert.Equal(t, "trl:cfg-1:consumer:co-9:hdr:user-1:model:claude-opus-*", modelKey(base, "claude-opus-*"))
}

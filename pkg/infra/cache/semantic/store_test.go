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

package semantic

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseSearch(t *testing.T) {
	tests := []struct {
		name string
		res  []interface{}
		want []Candidate
	}{
		{
			name: "empty",
			res:  []interface{}{int64(0)},
			want: nil,
		},
		{
			name: "single hit",
			res: []interface{}{
				int64(1),
				"semantic_cache:abc:1",
				[]interface{}{"response", "cached body", "__embedding_score", "0.05"},
			},
			want: []Candidate{{Response: "cached body", Similarity: 0.95}},
		},
		{
			name: "skips entries without response",
			res: []interface{}{
				int64(1),
				"semantic_cache:abc:1",
				[]interface{}{"__embedding_score", "0.10"},
			},
			want: []Candidate{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseSearch(tt.res)
			if len(tt.want) == 0 {
				assert.Empty(t, got)
				return
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestHashID_Deterministic(t *testing.T) {
	assert.Equal(t, hashID("rule-1"), hashID("rule-1"))
	assert.NotEqual(t, hashID("rule-1"), hashID("rule-2"))
	assert.Len(t, hashID("x"), 64)
}

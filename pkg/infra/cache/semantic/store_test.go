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

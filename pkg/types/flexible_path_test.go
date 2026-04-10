package types

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFlexiblePath_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantPrimary string
		wantAll     []string
		wantErr     bool
	}{
		{
			name:        "single string path",
			input:       `"/v1/chat"`,
			wantPrimary: "/v1/chat",
			wantAll:     nil,
		},
		{
			name:        "multi-path array",
			input:       `["/v1/foo/{id}", "/v2/foo/{id}"]`,
			wantPrimary: "/v1/foo/{id}",
			wantAll:     []string{"/v1/foo/{id}", "/v2/foo/{id}"},
		},
		{
			name:        "single-element array",
			input:       `["/v1/only"]`,
			wantPrimary: "/v1/only",
			wantAll:     []string{"/v1/only"},
		},
		{
			name:    "empty array",
			input:   `[]`,
			wantErr: true,
		},
		{
			name:    "invalid type number",
			input:   `123`,
			wantErr: true,
		},
		{
			name:    "invalid type object",
			input:   `{"path": "/v1"}`,
			wantErr: true,
		},
		{
			name:        "empty string",
			input:       `""`,
			wantPrimary: "",
			wantAll:     nil,
		},
		{
			name:        "three paths",
			input:       `["/a", "/b", "/c"]`,
			wantPrimary: "/a",
			wantAll:     []string{"/a", "/b", "/c"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var fp FlexiblePath
			err := json.Unmarshal([]byte(tt.input), &fp)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantPrimary, fp.Primary)
			assert.Equal(t, tt.wantAll, fp.All)
		})
	}
}

func TestFlexiblePath_MarshalJSON(t *testing.T) {
	tests := []struct {
		name     string
		fp       FlexiblePath
		wantJSON string
	}{
		{
			name:     "single path marshals as string",
			fp:       FlexiblePath{Primary: "/v1/chat"},
			wantJSON: `"/v1/chat"`,
		},
		{
			name:     "multi-path marshals as array",
			fp:       FlexiblePath{Primary: "/v1/a", All: []string{"/v1/a", "/v2/a"}},
			wantJSON: `["/v1/a","/v2/a"]`,
		},
		{
			name:     "single-element array marshals as array",
			fp:       FlexiblePath{Primary: "/v1/only", All: []string{"/v1/only"}},
			wantJSON: `["/v1/only"]`,
		},
		{
			name:     "empty primary no all",
			fp:       FlexiblePath{Primary: ""},
			wantJSON: `""`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.fp)
			require.NoError(t, err)
			assert.JSONEq(t, tt.wantJSON, string(data))
		})
	}
}

func TestFlexiblePath_IsMultiPath(t *testing.T) {
	tests := []struct {
		name string
		fp   FlexiblePath
		want bool
	}{
		{
			name: "single path",
			fp:   FlexiblePath{Primary: "/v1/chat"},
			want: false,
		},
		{
			name: "multi-path",
			fp:   FlexiblePath{Primary: "/v1/a", All: []string{"/v1/a", "/v2/a"}},
			want: true,
		},
		{
			name: "nil all",
			fp:   FlexiblePath{Primary: "/v1/a", All: nil},
			want: false,
		},
		{
			name: "empty all slice",
			fp:   FlexiblePath{Primary: "/v1/a", All: []string{}},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.fp.IsMultiPath())
		})
	}
}

func TestFlexiblePath_RoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "string round-trip",
			input: `"/v1/chat/send"`,
		},
		{
			name:  "array round-trip",
			input: `["/v1/a","/v2/b"]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var fp FlexiblePath
			require.NoError(t, json.Unmarshal([]byte(tt.input), &fp))

			data, err := json.Marshal(fp)
			require.NoError(t, err)
			assert.JSONEq(t, tt.input, string(data))
		})
	}
}

func TestFlexiblePath_InStruct(t *testing.T) {
	type Request struct {
		Path FlexiblePath `json:"path"`
		Name string       `json:"name"`
	}

	t.Run("struct with string path", func(t *testing.T) {
		input := `{"path": "/v1/chat", "name": "test"}`
		var r Request
		require.NoError(t, json.Unmarshal([]byte(input), &r))
		assert.Equal(t, "/v1/chat", r.Path.Primary)
		assert.False(t, r.Path.IsMultiPath())
	})

	t.Run("struct with array path", func(t *testing.T) {
		input := `{"path": ["/v1/a", "/v2/a"], "name": "test"}`
		var r Request
		require.NoError(t, json.Unmarshal([]byte(input), &r))
		assert.Equal(t, "/v1/a", r.Path.Primary)
		assert.True(t, r.Path.IsMultiPath())
		assert.Equal(t, []string{"/v1/a", "/v2/a"}, r.Path.All)
	})
}

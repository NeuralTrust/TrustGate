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

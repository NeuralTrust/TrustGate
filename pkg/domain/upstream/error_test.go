package upstream_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/upstream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpstreamError_Error(t *testing.T) {
	ue := upstream.NewUpstreamError(400, []byte(`{"error":"bad request"}`))
	assert.Equal(t, "upstream responded with status 400", ue.Error())
}

func TestUpstreamError_Fields(t *testing.T) {
	body := []byte(`{"error":{"message":"Missing model"}}`)
	ue := upstream.NewUpstreamError(422, body)

	assert.Equal(t, 422, ue.StatusCode)
	assert.Equal(t, body, ue.Body)
}

func TestIsUpstreamError_Match(t *testing.T) {
	original := upstream.NewUpstreamError(429, []byte(`rate limited`))
	wrapped := fmt.Errorf("completions failed: %w", original)

	ue, ok := upstream.IsUpstreamError(wrapped)
	require.True(t, ok)
	assert.Equal(t, 429, ue.StatusCode)
	assert.Equal(t, []byte(`rate limited`), ue.Body)
}

func TestIsUpstreamError_NoMatch(t *testing.T) {
	plain := errors.New("connection refused")
	ue, ok := upstream.IsUpstreamError(plain)
	assert.False(t, ok)
	assert.Nil(t, ue)
}

func TestIsUpstreamError_Nil(t *testing.T) {
	ue, ok := upstream.IsUpstreamError(nil)
	assert.False(t, ok)
	assert.Nil(t, ue)
}

func TestUpstreamError_ImplementsError(t *testing.T) {
	var err error = upstream.NewUpstreamError(500, []byte("internal"))
	assert.Error(t, err)
}

func TestIsUpstreamError_DirectMatch(t *testing.T) {
	ue := upstream.NewUpstreamError(503, []byte(`service unavailable`))
	found, ok := upstream.IsUpstreamError(ue)
	require.True(t, ok)
	assert.Equal(t, 503, found.StatusCode)
}

func TestIsHTTPError(t *testing.T) {
	tests := []struct {
		code int
		want bool
	}{
		{199, true},
		{200, false},
		{201, false},
		{204, false},
		{299, false},
		{300, true},
		{301, true},
		{400, true},
		{401, true},
		{404, true},
		{429, true},
		{500, true},
		{502, true},
		{503, true},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("status_%d", tt.code), func(t *testing.T) {
			assert.Equal(t, tt.want, upstream.IsHTTPError(tt.code))
		})
	}
}

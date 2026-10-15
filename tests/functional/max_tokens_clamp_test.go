//go:build functional

package functional_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newFailOnceThenOKUpstream(t *testing.T, marker string) *fakeUpstream {
	t.Helper()
	u := &fakeUpstream{}
	u.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.record(r)
		hit := atomic.LoadInt64(&u.hits)
		w.Header().Set("Content-Type", "application/json")
		if hit == 1 {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"error":{"type":"invalid_request_error","param":"max_tokens","message":"max_tokens is too large: 32000. This model supports at most 16384 completion tokens, whereas you provided 32000."}}`)
			return
		}
		_, _ = fmt.Fprintf(w,
			`{"id":"chatcmpl-test","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":%q},"finish_reason":"stop"}]}`,
			marker,
		)
	}))
	t.Cleanup(u.server.Close)
	return u
}

func TestMaxTokensClamp_RetryAndLearn(t *testing.T) {
	defer Track(t, "MaxTokensClamp")()

	up := newFailOnceThenOKUpstream(t, "clamped-ok")
	model := uniqueName("clamp-learn")
	apiKey, slug := setupSlugRoute(t, up, []string{model}, "")
	payload := anthropicChatRequest(model)
	payload["max_tokens"] = 32000

	status, headers, body := proxyPost(t, apiKey, "/"+slug+"/v1/messages", payload)

	require.Equal(t, http.StatusOK, status, "body: %s", body)
	assert.Equal(t, 2, up.Hits())
	assert.Contains(t, string(up.LastBody()), `"max_completion_tokens":16384`)
	assert.Equal(t, "16384", headers.Get("X-Max-Tokens-Clamped"))

	status, headers, body = proxyPost(t, apiKey, "/"+slug+"/v1/messages", payload)
	require.Equal(t, http.StatusOK, status, "body: %s", body)
	assert.Equal(t, 3, up.Hits())
	assert.Contains(t, string(up.LastBody()), `"max_completion_tokens":16384`)
	assert.Equal(t, "16384", headers.Get("X-Max-Tokens-Clamped"))
}

func TestMaxTokensClamp_Generic400DoesNotRetry(t *testing.T) {
	defer Track(t, "MaxTokensClamp")()

	up := newFailingUpstream(t, http.StatusBadRequest)
	model := uniqueName("clamp-generic")
	apiKey, slug := setupSlugRoute(t, up, []string{model}, "")
	payload := anthropicChatRequest(model)
	payload["max_tokens"] = 32000

	status, headers, _ := proxyPost(t, apiKey, "/"+slug+"/v1/messages", payload)

	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, 1, up.Hits())
	assert.Empty(t, headers.Get("X-Max-Tokens-Clamped"))
}

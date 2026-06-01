package providers

import (
	"bytes"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPClientPool_GetReturnsSameInstancePerKey(t *testing.T) {
	pool := NewHTTPClientPool()

	a1 := pool.Get("openai", 5*time.Second)
	a2 := pool.Get("openai", 5*time.Second)
	b1 := pool.Get("anthropic", 5*time.Second)

	require.NotNil(t, a1)
	require.NotNil(t, b1)
	assert.Same(t, a1, a2, "same key must return the same client instance")
	assert.NotSame(t, a1, b1, "different keys must return different client instances")
	assert.Equal(t, 5*time.Second, a1.Timeout)
}

func TestHTTPClientPool_GetConcurrentSameKey(t *testing.T) {
	pool := NewHTTPClientPool()

	const goroutines = 50
	clients := make([]any, goroutines)
	done := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			clients[idx] = pool.Get("openai", time.Second)
			done <- struct{}{}
		}(i)
	}
	for i := 0; i < goroutines; i++ {
		<-done
	}

	first := clients[0]
	for i := 1; i < goroutines; i++ {
		assert.Same(t, first, clients[i], "concurrent Get for the same key must return one instance")
	}
}

func TestSetDefaultHTTPTimeout(t *testing.T) {
	original := DefaultHTTPTimeout
	t.Cleanup(func() { DefaultHTTPTimeout = original })

	SetDefaultHTTPTimeout(42 * time.Second)
	assert.Equal(t, 42*time.Second, DefaultHTTPTimeout)

	SetDefaultHTTPTimeout(0)
	assert.Equal(t, 42*time.Second, DefaultHTTPTimeout, "non-positive duration must be ignored")
}

func TestDrainBody(t *testing.T) {
	rc := io.NopCloser(bytes.NewReader([]byte("some leftover body bytes")))
	DrainBody(rc)
	// A second close on the underlying NopCloser is a no-op; the call must not panic.
}

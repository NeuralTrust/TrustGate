package bedrock

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewClient(t *testing.T) {
	c := NewClient()
	require.NotNil(t, c)
	assert.Nil(t, c.GetRuntimeClient(), "runtime client is nil until BuildClient is called")
}

func TestBuildClient_SameKeyConcurrent_ReturnsSameInstance(t *testing.T) {
	t.Parallel()

	c := NewClient()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)
	runtimeClients := make([]any, goroutines)

	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			cl, err := c.BuildClient(ctx, "AKIA_TEST", "SECRET_TEST", "", "us-east-1", false, "", "")
			if err != nil {
				t.Errorf("BuildClient failed: %v", err)
				return
			}
			runtimeClients[i] = cl.GetRuntimeClient()
		}()
	}
	wg.Wait()

	first := runtimeClients[0]
	for i := 1; i < goroutines; i++ {
		assert.Same(t, first, runtimeClients[i], "identical keys must return the same runtime client")
	}
}

func TestBuildClient_DifferentKeys_ReturnDifferentInstances(t *testing.T) {
	t.Parallel()

	c := NewClient()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cl1, err := c.BuildClient(ctx, "AKIA_TEST", "SECRET_TEST", "", "us-east-1", false, "", "")
	require.NoError(t, err)
	cl2, err := c.BuildClient(ctx, "AKIA_TEST", "SECRET_TEST", "", "us-east-2", false, "", "")
	require.NoError(t, err)

	assert.NotSame(t, cl1.GetRuntimeClient(), cl2.GetRuntimeClient(), "different regions must return different instances")
}

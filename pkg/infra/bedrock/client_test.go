package bedrock

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestBuildClient_SameKeyConcurrent_ReturnsSameInstance(t *testing.T) {
	t.Parallel()

	c := NewClient()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	const (
		accessKey    = "AKIA_TEST"
		secretKey    = "SECRET_TEST"
		sessionToken = ""
		region       = "us-east-1"
		useRole      = false
		roleARN      = ""
		sessionName  = ""
	)

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)

	runtimeClients := make([]any, goroutines)

	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			cl, err := c.BuildClient(ctx, accessKey, secretKey, sessionToken, region, useRole, roleARN, sessionName)
			if err != nil {
				t.Errorf("BuildClient failed: %v", err)
				return
			}
			runtimeClients[i] = cl.GetRuntimeClient()
		}()
	}

	wg.Wait()

	// All returned runtime clients should be the same pointer
	first := runtimeClients[0]
	for i := 1; i < goroutines; i++ {
		assert.Same(t, first, runtimeClients[i], "expected same runtime client instance for identical keys")
	}
}

func TestBuildClient_DifferentKeys_ReturnDifferentInstances(t *testing.T) {
	t.Parallel()

	c := NewClient()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cl1, err := c.BuildClient(ctx, "AKIA_TEST", "SECRET_TEST", "", "us-east-1", false, "", "")
	assert.NoError(t, err)
	cl2, err := c.BuildClient(ctx, "AKIA_TEST", "SECRET_TEST", "", "us-east-2", false, "", "")
	assert.NoError(t, err)

	// Expect different pointers because the region differs
	assert.NotSame(t, cl1.GetRuntimeClient(), cl2.GetRuntimeClient(), "expected different instances for different keys")
}

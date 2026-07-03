package configsync

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadinessCheck_RedUntilSnapshotPresent(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore[string]()
	check := ReadinessCheck[string](store)

	require.ErrorIs(t, check(context.Background()), ErrNotReady)

	store.Swap(&Versioned[string]{Version: "v1", Snapshot: "ready", Raw: []byte("ready")})

	assert.NoError(t, check(context.Background()))
}

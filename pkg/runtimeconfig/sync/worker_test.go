package configsync

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fetchResult struct {
	raw         []byte
	version     string
	notModified bool
	err         error
}

type fakeFetcher struct {
	mu      sync.Mutex
	results []fetchResult
	idx     int
	calls   int
	etags   []string
}

func (f *fakeFetcher) Fetch(_ context.Context, etag string) ([]byte, string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.etags = append(f.etags, etag)
	if f.idx >= len(f.results) {
		return nil, "", true, nil
	}
	r := f.results[f.idx]
	if f.idx < len(f.results)-1 {
		f.idx++
	}
	return r.raw, r.version, r.notModified, r.err
}

func (f *fakeFetcher) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

type watchMsg struct {
	id      string
	version string
	err     error
}

type fakeNotifier struct {
	tailID  string
	tailErr error
	ch      chan watchMsg
	mu      sync.Mutex
	watched int
}

func (n *fakeNotifier) Tail(context.Context) (string, error) {
	return n.tailID, n.tailErr
}

func (n *fakeNotifier) Watch(ctx context.Context, _ string) (string, string, error) {
	n.mu.Lock()
	n.watched++
	n.mu.Unlock()
	select {
	case <-ctx.Done():
		return "", "", ctx.Err()
	case m, ok := <-n.ch:
		if !ok {
			<-ctx.Done()
			return "", "", ctx.Err()
		}
		return m.id, m.version, m.err
	}
}

func (n *fakeNotifier) Publish(context.Context, string) (string, error) {
	return "1-0", nil
}

type failingDecodeCodec struct{}

func (failingDecodeCodec) Encode(snapshot string) ([]byte, error) { return []byte(snapshot), nil }
func (failingDecodeCodec) Decode([]byte) (string, error)          { return "", errors.New("decode boom") }
func (failingDecodeCodec) Version([]byte) string                  { return "x" }

func snapshotOf(t *testing.T, store ConfigStore[string]) (string, bool) {
	t.Helper()
	v, ok := store.Load()
	if !ok {
		return "", false
	}
	return v.Snapshot, true
}

func TestWorker_Converge200Swaps(t *testing.T) {
	t.Parallel()

	raw := []byte("fresh")
	fetcher := &fakeFetcher{results: []fetchResult{{raw: raw, version: stringCodec{}.Version(raw)}}}
	store := NewMemoryStore[string]()
	worker := NewWorker[string](fetcher, store, &fakeNotifier{}, nil, stringCodec{}, nil, WorkerConfig{})

	require.NoError(t, worker.Converge(context.Background()))

	snap, ok := snapshotOf(t, store)
	require.True(t, ok)
	assert.Equal(t, "fresh", snap)
	assert.NotEmpty(t, store.Version())
}

func TestWorker_ConvergeMissingVersionRejected(t *testing.T) {
	t.Parallel()

	fetcher := &fakeFetcher{results: []fetchResult{{raw: []byte("no-etag")}}}
	store := NewMemoryStore[string]()
	worker := NewWorker[string](fetcher, store, &fakeNotifier{}, nil, stringCodec{}, nil, WorkerConfig{})

	err := worker.Converge(context.Background())
	require.ErrorIs(t, err, ErrIntegrity)
	_, ok := store.Load()
	assert.False(t, ok)
}

func TestWorker_Converge304Keeps(t *testing.T) {
	t.Parallel()

	fetcher := &fakeFetcher{results: []fetchResult{{notModified: true}}}
	store := NewMemoryStore[string]()
	current := &Versioned[string]{Version: "v1", Snapshot: "current", Raw: []byte("current")}
	store.Swap(current)

	worker := NewWorker[string](fetcher, store, &fakeNotifier{}, nil, stringCodec{}, nil, WorkerConfig{})
	require.NoError(t, worker.Converge(context.Background()))

	got, ok := store.Load()
	require.True(t, ok)
	assert.Same(t, current, got)
	assert.Equal(t, []string{"v1"}, fetcher.etags)
}

func TestWorker_ConvergeFetchError(t *testing.T) {
	t.Parallel()

	fetcher := &fakeFetcher{results: []fetchResult{{err: errors.New("boom")}}}
	store := NewMemoryStore[string]()
	worker := NewWorker[string](fetcher, store, &fakeNotifier{}, nil, stringCodec{}, nil, WorkerConfig{})

	err := worker.Converge(context.Background())
	require.Error(t, err)
	_, ok := store.Load()
	assert.False(t, ok)
}

func TestWorker_ConvergeDecodeError(t *testing.T) {
	t.Parallel()

	fetcher := &fakeFetcher{results: []fetchResult{{raw: []byte("bytes")}}}
	store := NewMemoryStore[string]()
	worker := NewWorker[string](fetcher, store, &fakeNotifier{}, nil, failingDecodeCodec{}, nil, WorkerConfig{})

	err := worker.Converge(context.Background())
	require.Error(t, err)
	_, ok := store.Load()
	assert.False(t, ok)
}

func TestWorker_ConvergeIntegrityMismatchKeepsCurrent(t *testing.T) {
	t.Parallel()

	fetcher := &fakeFetcher{results: []fetchResult{{raw: []byte("tampered"), version: "not-the-hash"}}}
	store := NewMemoryStore[string]()
	current := &Versioned[string]{Version: "v1", Snapshot: "current", Raw: []byte("current")}
	store.Swap(current)

	worker := NewWorker[string](fetcher, store, &fakeNotifier{}, nil, stringCodec{}, nil, WorkerConfig{})

	err := worker.Converge(context.Background())
	require.ErrorIs(t, err, ErrIntegrity)

	got, ok := store.Load()
	require.True(t, ok)
	assert.Same(t, current, got)
}

func TestWorker_ConvergeIntegrityMatchSwaps(t *testing.T) {
	t.Parallel()

	raw := []byte("fresh")
	version := stringCodec{}.Version(raw)
	fetcher := &fakeFetcher{results: []fetchResult{{raw: raw, version: version}}}
	store := NewMemoryStore[string]()

	worker := NewWorker[string](fetcher, store, &fakeNotifier{}, nil, stringCodec{}, nil, WorkerConfig{})
	require.NoError(t, worker.Converge(context.Background()))

	snap, ok := snapshotOf(t, store)
	require.True(t, ok)
	assert.Equal(t, "fresh", snap)
	assert.Equal(t, version, store.Version())
}

func TestWorker_RunWatchTriggersConverge(t *testing.T) {
	t.Parallel()

	fetcher := &fakeFetcher{results: []fetchResult{
		{raw: []byte("initial"), version: stringCodec{}.Version([]byte("initial"))},
		{raw: []byte("updated"), version: stringCodec{}.Version([]byte("updated"))},
		{notModified: true},
	}}
	notifier := &fakeNotifier{tailID: streamStart, ch: make(chan watchMsg, 1)}
	notifier.ch <- watchMsg{id: "5-0", version: "v2"}

	store := NewMemoryStore[string]()
	worker := NewWorker[string](fetcher, store, notifier, nil, stringCodec{}, nil, WorkerConfig{
		PollInterval: time.Hour,
		MinBackoff:   time.Millisecond,
		MaxBackoff:   5 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- worker.Run(ctx) }()

	require.Eventually(t, func() bool {
		snap, ok := snapshotOf(t, store)
		return ok && snap == "updated"
	}, 2*time.Second, 5*time.Millisecond)

	cancel()
	select {
	case err := <-done:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not exit after cancel")
	}
}

func TestWorker_RunBacksOffOnWatchError(t *testing.T) {
	t.Parallel()

	fetcher := &fakeFetcher{results: []fetchResult{
		{raw: []byte("initial"), version: stringCodec{}.Version([]byte("initial"))},
		{raw: []byte("recovered"), version: stringCodec{}.Version([]byte("recovered"))},
		{notModified: true},
	}}
	notifier := &fakeNotifier{tailID: streamStart, ch: make(chan watchMsg, 2)}
	notifier.ch <- watchMsg{err: errors.New("watch boom")}
	notifier.ch <- watchMsg{id: "6-0", version: "v3"}

	store := NewMemoryStore[string]()
	worker := NewWorker[string](fetcher, store, notifier, nil, stringCodec{}, nil, WorkerConfig{
		PollInterval: time.Hour,
		MinBackoff:   time.Millisecond,
		MaxBackoff:   5 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- worker.Run(ctx) }()

	require.Eventually(t, func() bool {
		snap, ok := snapshotOf(t, store)
		return ok && snap == "recovered"
	}, 2*time.Second, 5*time.Millisecond)

	cancel()
	select {
	case err := <-done:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not exit after cancel")
	}
	assert.GreaterOrEqual(t, fetcher.callCount(), 2)
}

func TestWorker_RunCtxCancelExitsImmediately(t *testing.T) {
	t.Parallel()

	fetcher := &fakeFetcher{results: []fetchResult{{notModified: true}}}
	notifier := &fakeNotifier{tailID: streamStart, ch: make(chan watchMsg)}
	store := NewMemoryStore[string]()
	worker := NewWorker[string](fetcher, store, notifier, nil, stringCodec{}, nil, WorkerConfig{
		PollInterval: time.Hour,
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- worker.Run(ctx) }()

	cancel()
	select {
	case err := <-done:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not exit after cancel")
	}
}

func TestWorker_RestoreLKG(t *testing.T) {
	t.Parallel()

	crypto, err := NewAESGCMCrypto(newTestKey())
	require.NoError(t, err)
	codec := stringCodec{}
	path := filepath.Join(t.TempDir(), "lkg.enc")
	lkg := NewLKGStore[string](crypto, codec, path)

	raw, err := codec.Encode("from-disk")
	require.NoError(t, err)
	require.NoError(t, lkg.Persist(&Versioned[string]{Version: codec.Version(raw), Snapshot: "from-disk", Raw: raw}))

	store := NewMemoryStore[string]()
	worker := NewWorker[string](&fakeFetcher{}, store, &fakeNotifier{}, lkg, codec, nil, WorkerConfig{})
	worker.restoreLKG()

	snap, ok := snapshotOf(t, store)
	require.True(t, ok)
	assert.Equal(t, "from-disk", snap)
}

func TestWorker_RestoreLKGCorruptDiscarded(t *testing.T) {
	t.Parallel()

	crypto, err := NewAESGCMCrypto(newTestKey())
	require.NoError(t, err)
	codec := stringCodec{}
	path := filepath.Join(t.TempDir(), "lkg.enc")
	require.NoError(t, writeCorrupt(path))
	lkg := NewLKGStore[string](crypto, codec, path)

	store := NewMemoryStore[string]()
	worker := NewWorker[string](&fakeFetcher{}, store, &fakeNotifier{}, lkg, codec, nil, WorkerConfig{})
	worker.restoreLKG()

	_, ok := store.Load()
	assert.False(t, ok)
}

func TestJittered_StaysWithinSpread(t *testing.T) {
	t.Parallel()

	const base = 10 * time.Second
	low := time.Duration(float64(base) * (1 - backstopJitterFraction))
	high := time.Duration(float64(base) * (1 + backstopJitterFraction))

	for i := 0; i < 1000; i++ {
		got := jittered(base)
		assert.GreaterOrEqual(t, got, low)
		assert.LessOrEqual(t, got, high)
	}

	assert.Equal(t, time.Duration(0), jittered(0))
}

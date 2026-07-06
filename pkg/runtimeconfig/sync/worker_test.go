// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
	version string
	err     error
}

type fakeTransport struct {
	ch   chan watchMsg
	mu   sync.Mutex
	acks []string
}

func (t *fakeTransport) Watch(ctx context.Context) (string, error) {
	if t.ch == nil {
		<-ctx.Done()
		return "", ctx.Err()
	}
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case m, ok := <-t.ch:
		if !ok {
			<-ctx.Done()
			return "", ctx.Err()
		}
		return m.version, m.err
	}
}

func (t *fakeTransport) Ack(_ context.Context, appliedVersion string) error {
	t.mu.Lock()
	t.acks = append(t.acks, appliedVersion)
	t.mu.Unlock()
	return nil
}

func (t *fakeTransport) ackedVersions() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string(nil), t.acks...)
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
	transport := &fakeTransport{}
	worker := NewWorker[string](fetcher, store, transport, nil, stringCodec{}, nil, WorkerConfig{})

	require.NoError(t, worker.Converge(context.Background()))

	snap, ok := snapshotOf(t, store)
	require.True(t, ok)
	assert.Equal(t, "fresh", snap)
	assert.NotEmpty(t, store.Version())
	assert.Equal(t, []string{store.Version()}, transport.ackedVersions())
}

func TestWorker_ConvergeInvokesOnAppliedForNewVersion(t *testing.T) {
	t.Parallel()

	raw := []byte("fresh")
	fetcher := &fakeFetcher{results: []fetchResult{{raw: raw, version: stringCodec{}.Version(raw)}}}
	store := NewMemoryStore[string]()
	var applied int
	worker := NewWorker[string](fetcher, store, &fakeTransport{}, nil, stringCodec{}, nil, WorkerConfig{},
		WithOnApplied[string](func(context.Context) { applied++ }))

	require.NoError(t, worker.Converge(context.Background()))
	assert.Equal(t, 1, applied)
}

func TestWorker_ConvergeSkipsOnAppliedWhenNotModified(t *testing.T) {
	t.Parallel()

	fetcher := &fakeFetcher{results: []fetchResult{{notModified: true}}}
	store := NewMemoryStore[string]()
	store.Swap(&Versioned[string]{Version: "v1", Snapshot: "current", Raw: []byte("current")})
	var applied int
	worker := NewWorker[string](fetcher, store, &fakeTransport{}, nil, stringCodec{}, nil, WorkerConfig{},
		WithOnApplied[string](func(context.Context) { applied++ }))

	require.NoError(t, worker.Converge(context.Background()))
	assert.Equal(t, 0, applied)
}

func TestWorker_ConvergeMissingVersionRejected(t *testing.T) {
	t.Parallel()

	fetcher := &fakeFetcher{results: []fetchResult{{raw: []byte("no-etag")}}}
	store := NewMemoryStore[string]()
	transport := &fakeTransport{}
	worker := NewWorker[string](fetcher, store, transport, nil, stringCodec{}, nil, WorkerConfig{})

	err := worker.Converge(context.Background())
	require.ErrorIs(t, err, ErrIntegrity)
	_, ok := store.Load()
	assert.False(t, ok)
	assert.Empty(t, transport.ackedVersions())
}

func TestWorker_Converge304Keeps(t *testing.T) {
	t.Parallel()

	fetcher := &fakeFetcher{results: []fetchResult{{notModified: true}}}
	store := NewMemoryStore[string]()
	current := &Versioned[string]{Version: "v1", Snapshot: "current", Raw: []byte("current")}
	store.Swap(current)

	transport := &fakeTransport{}
	worker := NewWorker[string](fetcher, store, transport, nil, stringCodec{}, nil, WorkerConfig{})
	require.NoError(t, worker.Converge(context.Background()))

	got, ok := store.Load()
	require.True(t, ok)
	assert.Same(t, current, got)
	assert.Equal(t, []string{"v1"}, fetcher.etags)
	assert.Empty(t, transport.ackedVersions())
}

func TestWorker_ConvergeFetchError(t *testing.T) {
	t.Parallel()

	fetcher := &fakeFetcher{results: []fetchResult{{err: errors.New("boom")}}}
	store := NewMemoryStore[string]()
	worker := NewWorker[string](fetcher, store, &fakeTransport{}, nil, stringCodec{}, nil, WorkerConfig{})

	err := worker.Converge(context.Background())
	require.Error(t, err)
	_, ok := store.Load()
	assert.False(t, ok)
}

func TestWorker_ConvergeDecodeError(t *testing.T) {
	t.Parallel()

	fetcher := &fakeFetcher{results: []fetchResult{{raw: []byte("bytes")}}}
	store := NewMemoryStore[string]()
	worker := NewWorker[string](fetcher, store, &fakeTransport{}, nil, failingDecodeCodec{}, nil, WorkerConfig{})

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

	transport := &fakeTransport{}
	worker := NewWorker[string](fetcher, store, transport, nil, stringCodec{}, nil, WorkerConfig{})

	err := worker.Converge(context.Background())
	require.ErrorIs(t, err, ErrIntegrity)

	got, ok := store.Load()
	require.True(t, ok)
	assert.Same(t, current, got)
	assert.Empty(t, transport.ackedVersions())
}

func TestWorker_ConvergeIntegrityMatchSwaps(t *testing.T) {
	t.Parallel()

	raw := []byte("fresh")
	version := stringCodec{}.Version(raw)
	fetcher := &fakeFetcher{results: []fetchResult{{raw: raw, version: version}}}
	store := NewMemoryStore[string]()

	transport := &fakeTransport{}
	worker := NewWorker[string](fetcher, store, transport, nil, stringCodec{}, nil, WorkerConfig{})
	require.NoError(t, worker.Converge(context.Background()))

	snap, ok := snapshotOf(t, store)
	require.True(t, ok)
	assert.Equal(t, "fresh", snap)
	assert.Equal(t, version, store.Version())
	assert.Equal(t, []string{version}, transport.ackedVersions())
}

func TestWorker_RunWatchTriggersConverge(t *testing.T) {
	t.Parallel()

	updatedVersion := stringCodec{}.Version([]byte("updated"))
	fetcher := &fakeFetcher{results: []fetchResult{
		{raw: []byte("initial"), version: stringCodec{}.Version([]byte("initial"))},
		{raw: []byte("updated"), version: updatedVersion},
		{notModified: true},
	}}
	transport := &fakeTransport{ch: make(chan watchMsg, 1)}
	transport.ch <- watchMsg{version: "v2"}

	store := NewMemoryStore[string]()
	worker := NewWorker[string](fetcher, store, transport, nil, stringCodec{}, nil, WorkerConfig{
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

	require.Eventually(t, func() bool {
		acks := transport.ackedVersions()
		return len(acks) > 0 && acks[len(acks)-1] == updatedVersion
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
	transport := &fakeTransport{ch: make(chan watchMsg, 2)}
	transport.ch <- watchMsg{err: errors.New("watch boom")}
	transport.ch <- watchMsg{version: "v3"}

	store := NewMemoryStore[string]()
	worker := NewWorker[string](fetcher, store, transport, nil, stringCodec{}, nil, WorkerConfig{
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

func TestWorker_RunBackstopConverges(t *testing.T) {
	t.Parallel()

	raw := []byte("backstop")
	version := stringCodec{}.Version(raw)
	fetcher := &fakeFetcher{results: []fetchResult{
		{notModified: true},
		{raw: raw, version: version},
		{notModified: true},
	}}
	transport := &fakeTransport{}
	store := NewMemoryStore[string]()
	worker := NewWorker[string](fetcher, store, transport, nil, stringCodec{}, nil, WorkerConfig{
		PollInterval: 10 * time.Millisecond,
		MinBackoff:   time.Millisecond,
		MaxBackoff:   5 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- worker.Run(ctx) }()

	require.Eventually(t, func() bool {
		snap, ok := snapshotOf(t, store)
		return ok && snap == "backstop"
	}, 2*time.Second, 5*time.Millisecond)

	cancel()
	select {
	case err := <-done:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not exit after cancel")
	}
}

func TestWorker_RunCtxCancelExitsImmediately(t *testing.T) {
	t.Parallel()

	fetcher := &fakeFetcher{results: []fetchResult{{notModified: true}}}
	transport := &fakeTransport{ch: make(chan watchMsg)}
	store := NewMemoryStore[string]()
	worker := NewWorker[string](fetcher, store, transport, nil, stringCodec{}, nil, WorkerConfig{
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
	worker := NewWorker[string](&fakeFetcher{}, store, &fakeTransport{}, lkg, codec, nil, WorkerConfig{})
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
	worker := NewWorker[string](&fakeFetcher{}, store, &fakeTransport{}, lkg, codec, nil, WorkerConfig{})
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

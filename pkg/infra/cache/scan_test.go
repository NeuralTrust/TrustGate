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

package cache_test

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/clustertest"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func seedScanKeys(t *testing.T, server *miniredis.Miniredis, n int) []string {
	t.Helper()
	want := make([]string, 0, n)
	for i := range n {
		key := "scan:" + strconv.Itoa(i)
		require.NoError(t, server.Set(key, "v"))
		want = append(want, key)
	}
	require.NoError(t, server.Set("other:1", "v"))
	sort.Strings(want)
	return want
}

func collect(t *testing.T, rdb redis.UniversalClient) []string {
	t.Helper()
	var got []string
	require.NoError(t, cache.ScanKeys(t.Context(), rdb, "scan:*", 50, func(_ context.Context, keys []string) error {
		got = append(got, keys...)
		return nil
	}))
	sort.Strings(got)
	return got
}

func TestScanKeysStandaloneDrainsEveryPage(t *testing.T) {
	server := miniredis.RunT(t)
	want := seedScanKeys(t, server, 260)
	rdb := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	require.Equal(t, want, collect(t, rdb))
}

// The cluster test client rejects a SCAN sent through the cluster client, so
// only a scan of each master reaches the keys.
func TestScanKeysClusterScansEachMaster(t *testing.T) {
	server := miniredis.RunT(t)
	want := seedScanKeys(t, server, 260)
	rdb := clustertest.NewCluster(server.Addr())
	t.Cleanup(func() { _ = rdb.Close() })
	require.Equal(t, want, collect(t, rdb))
}

func TestScanKeysStopsEarlyWithoutError(t *testing.T) {
	server := miniredis.RunT(t)
	seedScanKeys(t, server, 260)
	for name, rdb := range map[string]redis.UniversalClient{
		"standalone": redis.NewClient(&redis.Options{Addr: server.Addr()}),
		"cluster":    clustertest.NewCluster(server.Addr()),
	} {
		t.Run(name, func(t *testing.T) {
			t.Cleanup(func() { _ = rdb.Close() })
			calls := 0
			err := cache.ScanKeys(t.Context(), rdb, "scan:*", 10, func(context.Context, []string) error {
				calls++
				return cache.ErrStopScan
			})
			require.NoError(t, err)
			require.Equal(t, 1, calls)
		})
	}
}

func TestScanKeysReturnsCallbackAndScanErrors(t *testing.T) {
	server := miniredis.RunT(t)
	seedScanKeys(t, server, 5)
	rdb := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	boom := errors.New("boom")
	err := cache.ScanKeys(t.Context(), rdb, "scan:*", 10, func(context.Context, []string) error { return boom })
	require.ErrorIs(t, err, boom)

	server.SetError("LOADING")
	err = cache.ScanKeys(t.Context(), rdb, "scan:*", 10, func(context.Context, []string) error { return nil })
	require.ErrorContains(t, err, `scan "scan:*"`)
}

// twoMasterCluster returns a cluster client whose slots are split between two
// test servers, so ForEachMaster scans both at the same time.
func twoMasterCluster(t *testing.T) (*redis.ClusterClient, *miniredis.Miniredis, *miniredis.Miniredis) {
	t.Helper()
	first, second := miniredis.RunT(t), miniredis.RunT(t)
	rdb := redis.NewClusterClient(&redis.ClusterOptions{
		ClusterSlots: func(context.Context) ([]redis.ClusterSlot, error) {
			return []redis.ClusterSlot{
				{Start: 0, End: 8191, Nodes: []redis.ClusterNode{{Addr: first.Addr()}}},
				{Start: 8192, End: 16383, Nodes: []redis.ClusterNode{{Addr: second.Addr()}}},
			}, nil
		},
	})
	t.Cleanup(func() { _ = rdb.Close() })
	return rdb, first, second
}

func TestScanKeysClusterStopWinsOverAFailingMaster(t *testing.T) {
	rdb, first, second := twoMasterCluster(t)
	require.NoError(t, second.Set("scan:found", "v"))
	first.SetError("LOADING")
	for range 50 {
		found := false
		err := cache.ScanKeys(t.Context(), rdb, "scan:*", 10, func(context.Context, []string) error {
			found = true
			return cache.ErrStopScan
		})
		require.NoError(t, err)
		require.True(t, found)
	}
}

func TestScanKeysClusterReturnsTheFirstCallbackError(t *testing.T) {
	rdb, first, second := twoMasterCluster(t)
	seedScanKeys(t, first, 30)
	seedScanKeys(t, second, 30)
	boom := errors.New("boom")
	for range 50 {
		calls := 0
		err := cache.ScanKeys(t.Context(), rdb, "scan:*", 10, func(context.Context, []string) error {
			calls++
			return boom
		})
		require.ErrorIs(t, err, boom)
		require.Equal(t, 1, calls)
	}
}

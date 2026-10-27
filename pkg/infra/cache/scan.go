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

package cache

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/redis/go-redis/v9"
)

// ErrStopScan, returned by the callback of ScanKeys, ends the scan early
// without an error.
var ErrStopScan = errors.New("cache: stop scan")

// ScanKeys calls fn with each batch of keys that match pattern. A SCAN sent
// through a cluster client reaches a single node and silently misses the keys
// of every other shard, so on a cluster each master is scanned on its own. fn
// is never called concurrently, and keys it receives may be used with rdb.
// On a cluster a stop or an error from fn ends the scan of every master. A
// master whose SCAN fails does not end the others, and its error is returned
// only when fn neither stops nor fails.
func ScanKeys(ctx context.Context, rdb redis.UniversalClient, pattern string, count int64, fn func(ctx context.Context, keys []string) error) error {
	cluster, ok := rdb.(*redis.ClusterClient)
	if !ok {
		return ignoreStop(scanNode(ctx, rdb, pattern, count, fn))
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// ForEachMaster keeps whichever error arrives first and never cancels the
	// other masters, so the outcome is tracked here instead.
	var (
		mutex     sync.Mutex
		stopped   bool
		failure   error
		nodeError error
	)
	serial := func(ctx context.Context, keys []string) error {
		mutex.Lock()
		defer mutex.Unlock()
		if stopped || failure != nil {
			return ErrStopScan
		}
		err := fn(ctx, keys)
		switch {
		case errors.Is(err, ErrStopScan):
			stopped = true
			cancel()
		case err != nil:
			failure = err
			cancel()
		}
		return err
	}
	err := cluster.ForEachMaster(ctx, func(ctx context.Context, node *redis.Client) error {
		err := scanNode(ctx, node, pattern, count, serial)
		if err != nil && !errors.Is(err, ErrStopScan) {
			mutex.Lock()
			if nodeError == nil && failure == nil {
				nodeError = err
			}
			mutex.Unlock()
		}
		return err
	})
	mutex.Lock()
	defer mutex.Unlock()
	switch {
	case stopped:
		return nil
	case failure != nil:
		return failure
	case nodeError != nil:
		return nodeError
	default:
		return ignoreStop(err)
	}
}

func scanNode(ctx context.Context, node redis.Cmdable, pattern string, count int64, fn func(ctx context.Context, keys []string) error) error {
	var cursor uint64
	for {
		keys, next, err := node.Scan(ctx, cursor, pattern, count).Result()
		if err != nil {
			return fmt.Errorf("scan %q: %w", pattern, err)
		}
		if len(keys) > 0 {
			if err := fn(ctx, keys); err != nil {
				return err
			}
		}
		cursor = next
		if cursor == 0 {
			return nil
		}
	}
}

func ignoreStop(err error) error {
	if errors.Is(err, ErrStopScan) {
		return nil
	}
	return err
}

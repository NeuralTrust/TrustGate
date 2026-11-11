//go:build functional

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

package consumer_test

import (
	"context"
	"fmt"
	"testing"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/listing"
	"github.com/stretchr/testify/require"
)

// pagedIDs lists every consumer of gatewayID page by page, deleting the
// newest consumer of another gateway after the first page, the way a cascade
// delete lands in the middle of a snapshot compile's paged scan.
func pagedIDs(t *testing.T, ctx context.Context, f fixture, gatewayID ids.GatewayID, deleteAfterFirst func()) map[ids.ConsumerID]int {
	t.Helper()
	seen := map[ids.ConsumerID]int{}
	for page := 1; ; page++ {
		items, _, err := f.repo.List(ctx, domain.ListFilter{GatewayID: gatewayID, Page: listing.Page{Number: page, Size: 10}})
		require.NoError(t, err)
		for _, c := range items {
			seen[c.ID]++
		}
		if page == 1 {
			deleteAfterFirst()
		}
		if len(items) < 10 {
			return seen
		}
	}
}

func TestReadConsistent_PagedScanNeitherSkipsNorRepeatsRowsUnderConcurrentDeletes(t *testing.T) {
	f := setupRepo(t)
	ctx := context.Background()
	t.Cleanup(func() {
		_, _ = f.conn.Pool.Exec(context.Background(), "TRUNCATE TABLE config_snapshot_outbox")
	})

	gwID := seedGateway(t, f.gw, "paged-scan")
	var all []ids.ConsumerID
	for i := 0; i < 30; i++ {
		c := validConsumer(t, gwID, fmt.Sprintf("paged-%02d", i))
		require.NoError(t, f.repo.Save(ctx, c))
		all = append(all, c.ID)
	}
	// List orders by created_at DESC: the newest consumers sit on the first
	// page, so deleting them after it was read shifts every later page up.
	victims := all[len(all)-5:]
	deleteVictims := func() {
		for _, id := range victims {
			require.NoError(t, f.repo.Delete(context.Background(), gwID, id))
		}
	}

	var seen map[ids.ConsumerID]int
	require.NoError(t, f.conn.ReadConsistent(ctx, func(ctx context.Context) error {
		seen = pagedIDs(t, ctx, f, gwID, deleteVictims)
		return nil
	}))

	require.Len(t, seen, len(all), "a paged scan inside one read snapshot must see every row that existed when it started")
	for _, id := range all {
		require.Equal(t, 1, seen[id], "consumer %s read %d times", id, seen[id])
	}

	// The same scan outside a snapshot skips the rows the deletes pushed across
	// a page boundary, which is how a compile published a configuration with
	// consumers missing.
	more := make([]ids.ConsumerID, 0, 5)
	for i := 0; i < 5; i++ {
		c := validConsumer(t, gwID, fmt.Sprintf("paged-more-%02d", i))
		require.NoError(t, f.repo.Save(ctx, c))
		more = append(more, c.ID)
	}
	victims = more
	live := pagedIDs(t, ctx, f, gwID, deleteVictims)
	survivorsSeen := 0
	for _, id := range all[:len(all)-5] {
		if live[id] > 0 {
			survivorsSeen++
		}
	}
	require.Less(t, survivorsSeen, len(all)-5, "without a snapshot the scan is expected to skip rows that were never deleted")
}

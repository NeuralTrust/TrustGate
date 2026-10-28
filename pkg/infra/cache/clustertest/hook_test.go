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

package clustertest_test

import (
	"context"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/clustertest"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSlot(t *testing.T) {
	assert.Equal(t, 12182, clustertest.Slot("foo"))
	assert.Equal(t, 5061, clustertest.Slot("bar"))
	assert.Equal(t, 12739, clustertest.Slot("123456789"))
	assert.Equal(t, clustertest.Slot("{u}.a"), clustertest.Slot("{u}.b"))
	assert.NotEqual(t, clustertest.Slot("{}foo"), clustertest.Slot("{}bar"))
}

func TestHook(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := clustertest.New(redis.NewClient(&redis.Options{Addr: mr.Addr()}))
	t.Cleanup(func() { _ = rdb.Close() })
	ctx := context.Background()

	require.ErrorContains(t, rdb.MGet(ctx, "foo", "bar").Err(), "CROSSSLOT")
	require.ErrorContains(t, rdb.Del(ctx, "foo", "bar").Err(), "CROSSSLOT")
	require.NoError(t, rdb.MGet(ctx, "{t}foo", "{t}bar").Err())

	_, err := rdb.TxPipelined(ctx, func(p redis.Pipeliner) error {
		p.Set(ctx, "foo", 1, 0)
		p.Set(ctx, "bar", 1, 0)
		return nil
	})
	require.ErrorContains(t, err, "CROSSSLOT")

	_, err = rdb.Pipelined(ctx, func(p redis.Pipeliner) error {
		p.Set(ctx, "foo", 1, 0)
		p.Set(ctx, "bar", 1, 0)
		return nil
	})
	require.NoError(t, err)

	script := redis.NewScript(`return #KEYS`)
	require.ErrorContains(t, script.Run(ctx, rdb, []string{"foo", "bar"}).Err(), "CROSSSLOT")
	require.NoError(t, script.Run(ctx, rdb, []string{"{t}foo", "{t}bar"}).Err())
}

func TestNewClusterRejectsKeylessScanButNotPerMasterScan(t *testing.T) {
	mr := miniredis.RunT(t)
	require.NoError(t, mr.Set("foo", "1"))
	rdb := clustertest.NewCluster(mr.Addr())
	t.Cleanup(func() { _ = rdb.Close() })
	ctx := context.Background()

	require.ErrorContains(t, rdb.Scan(ctx, 0, "*", 10).Err(), clustertest.KeylessScanMessage)
	require.ErrorContains(t, rdb.Keys(ctx, "*").Err(), clustertest.KeylessScanMessage)
	require.ErrorContains(t, rdb.MGet(ctx, "foo", "bar").Err(), "CROSSSLOT")

	var found []string
	require.NoError(t, rdb.ForEachMaster(ctx, func(ctx context.Context, node *redis.Client) error {
		keys, _, err := node.Scan(ctx, 0, "*", 10).Result()
		found = append(found, keys...)
		return err
	}))
	require.Equal(t, []string{"foo"}, found)
}

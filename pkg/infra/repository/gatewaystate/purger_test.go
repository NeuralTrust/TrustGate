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

package gatewaystate_test

import (
	"strconv"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/infra/repository/gatewaystate"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func TestPurgeGatewayState_RemovesEveryKeyspaceOwnedByTheGateway(t *testing.T) {
	t.Parallel()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	deleted := ids.New[ids.GatewayKind]()
	survivor := ids.New[ids.GatewayKind]()
	registryID := ids.New[ids.RegistryKind]().String()

	// Key shapes as written by their owning components. The first two carry no
	// TTL, so nothing but this purge would ever reclaim them.
	owned := []string{
		"vault:" + deleted.String() + ":0dcc69fc-5f46-4224-a229-1cafec9eb767:app.linear/mcp",
		"oauth:dcr:client:" + deleted.String() + "|" + registryID,
		"session:" + deleted.String() + ":019fb33d",
		"gt:rl:burst:" + deleted.String(),
		"gt:rl:quota:" + deleted.String() + ":2026-08",
	}
	kept := []string{
		"vault:" + survivor.String() + ":0dcc69fc-5f46-4224-a229-1cafec9eb767:app.linear/mcp",
		"oauth:dcr:client:" + survivor.String() + "|" + registryID,
		"oauth:gwclient:agw-unscoped",
	}
	for _, key := range append(append([]string{}, owned...), kept...) {
		require.NoError(t, rdb.Set(t.Context(), key, "payload", 0).Err())
	}

	require.NoError(t, gatewaystate.NewPurger(rdb).PurgeGatewayState(t.Context(), deleted))

	for _, key := range owned {
		exists, err := rdb.Exists(t.Context(), key).Result()
		require.NoError(t, err)
		require.Equal(t, int64(0), exists, "key %s should have been purged", key)
	}
	for _, key := range kept {
		exists, err := rdb.Exists(t.Context(), key).Result()
		require.NoError(t, err)
		require.Equal(t, int64(1), exists, "key %s belongs to another gateway and must survive", key)
	}
}

func TestPurgeGatewayState_PagesThroughLargeKeyspaces(t *testing.T) {
	t.Parallel()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	deleted := ids.New[ids.GatewayKind]()
	const total = 550
	for i := 0; i < total; i++ {
		key := "vault:" + deleted.String() + ":principal-" + strconv.Itoa(i) + ":app.linear/mcp"
		require.NoError(t, rdb.Set(t.Context(), key, "payload", 0).Err())
	}

	require.NoError(t, gatewaystate.NewPurger(rdb).PurgeGatewayState(t.Context(), deleted))

	remaining, err := rdb.Keys(t.Context(), "*"+deleted.String()+"*").Result()
	require.NoError(t, err)
	require.Empty(t, remaining, "purge must drain every SCAN page")
}

func TestPurgeGatewayState_NilClientIsNoOp(t *testing.T) {
	t.Parallel()
	require.NoError(t, gatewaystate.NewPurger(nil).PurgeGatewayState(t.Context(), ids.New[ids.GatewayKind]()))
}

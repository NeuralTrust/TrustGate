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

package a2a

import (
	"context"
	"testing"
	"time"

	appa2a "github.com/NeuralTrust/TrustGate/pkg/app/a2a"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOwnershipStore(t *testing.T) {
	t.Parallel()
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	store := NewOwnershipStore(client)
	ctx := context.Background()
	key := appa2a.OwnershipKey{GatewayID: ids.New[ids.GatewayKind](), RegistryID: ids.New[ids.RegistryKind](), Scope: appa2a.ScopeContext, ID: "ctx-1"}
	redisKey := "a2a:own:" + key.GatewayID.String() + ":" + key.RegistryID.String() + ":c:ctx-1"
	u1 := appa2a.Owner{ConsumerID: ids.New[ids.ConsumerKind](), Subject: "u1", UpstreamSession: "s-1"}

	owner, err := store.Owner(ctx, key)
	require.NoError(t, err)
	assert.Nil(t, owner)

	claimed, existing, err := store.Claim(ctx, key, u1, time.Hour)
	require.NoError(t, err)
	assert.True(t, claimed)
	assert.Nil(t, existing)
	assert.Equal(t, time.Hour, server.TTL(redisKey))

	claimed, existing, err = store.Claim(ctx, key, appa2a.Owner{ConsumerID: u1.ConsumerID, Subject: "u2"}, time.Hour)
	require.NoError(t, err)
	assert.False(t, claimed)
	assert.Equal(t, &u1, existing)

	server.FastForward(30 * time.Minute)
	require.NoError(t, store.Touch(ctx, key, time.Hour))
	assert.Equal(t, time.Hour, server.TTL(redisKey))

	owner, err = store.Owner(ctx, key)
	require.NoError(t, err)
	assert.Equal(t, &u1, owner)

	server.FastForward(2 * time.Hour)
	owner, err = store.Owner(ctx, key)
	require.NoError(t, err)
	assert.Nil(t, owner, "an expired binding has no owner")

	server.Close()
	_, err = store.Owner(ctx, key)
	require.Error(t, err)
}

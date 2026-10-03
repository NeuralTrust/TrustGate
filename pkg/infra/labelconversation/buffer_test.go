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

package labelconversation

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/app/trafficlabels"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testKey = bytes.Repeat([]byte{7}, KeyLen)

func newTestBuffer(t *testing.T, ttl time.Duration, key []byte) (*Buffer, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	b, err := New(client, ttl, key)
	require.NoError(t, err)
	return b, mr
}

var convKey = trafficlabels.ConversationKey{GatewayID: "gw-1", ConsumerID: "consumer-1", SessionID: "sess-secret-1"}

func TestBuffer_RoundTripIsEncrypted(t *testing.T) {
	t.Parallel()
	b, mr := newTestBuffer(t, time.Hour, testKey)
	ctx := context.Background()

	msgs := []string{"I was charged twice", "INV-42"}
	require.NoError(t, b.Save(ctx, convKey, msgs))

	got, err := b.Load(ctx, convKey)
	require.NoError(t, err)
	assert.Equal(t, msgs, got)

	keys := mr.Keys()
	require.Len(t, keys, 1)
	assert.True(t, strings.HasPrefix(keys[0], keyPrefix))
	assert.NotContains(t, keys[0], "sess-secret-1", "the session id must not appear in the key name")
	raw, err := mr.Get(keys[0])
	require.NoError(t, err)
	assert.NotContains(t, raw, "charged", "the messages must be encrypted at rest")
	assert.NotContains(t, raw, "INV-42")
}

func TestBuffer_ScopedByGatewayConsumerAndSession(t *testing.T) {
	t.Parallel()
	b, _ := newTestBuffer(t, time.Hour, testKey)
	ctx := context.Background()
	require.NoError(t, b.Save(ctx, convKey, []string{"hello"}))

	for _, other := range []trafficlabels.ConversationKey{
		{GatewayID: "gw-2", ConsumerID: convKey.ConsumerID, SessionID: convKey.SessionID},
		{GatewayID: convKey.GatewayID, ConsumerID: "consumer-2", SessionID: convKey.SessionID},
		{GatewayID: convKey.GatewayID, ConsumerID: convKey.ConsumerID, SessionID: "sess-other"},
	} {
		got, err := b.Load(ctx, other)
		require.NoError(t, err)
		assert.Empty(t, got)
	}
}

func TestBuffer_SlidingTTL(t *testing.T) {
	t.Parallel()
	b, mr := newTestBuffer(t, 10*time.Minute, testKey)
	ctx := context.Background()
	require.NoError(t, b.Save(ctx, convKey, []string{"one"}))
	assert.Equal(t, 10*time.Minute, mr.TTL(b.redisKey(convKey)))

	mr.FastForward(8 * time.Minute)
	require.NoError(t, b.Save(ctx, convKey, []string{"one", "two"}))
	mr.FastForward(8 * time.Minute)
	got, err := b.Load(ctx, convKey)
	require.NoError(t, err)
	assert.Equal(t, []string{"one", "two"}, got, "every save restarts the TTL")

	mr.FastForward(11 * time.Minute)
	got, err = b.Load(ctx, convKey)
	require.NoError(t, err)
	assert.Empty(t, got, "an expired buffer reads as a miss")
}

func TestBuffer_RejectsTamperingAndForeignKeys(t *testing.T) {
	t.Parallel()
	b, mr := newTestBuffer(t, time.Hour, testKey)
	ctx := context.Background()
	require.NoError(t, b.Save(ctx, convKey, []string{"hello"}))
	name := b.redisKey(convKey)

	raw, err := mr.Get(name)
	require.NoError(t, err)
	tampered := []byte(raw)
	tampered[len(tampered)-1] ^= 0xff
	require.NoError(t, mr.Set(name, string(tampered)))
	_, err = b.Load(ctx, convKey)
	assert.Error(t, err)

	require.NoError(t, b.Save(ctx, convKey, []string{"hello"}))
	other, err := New(redis.NewClient(&redis.Options{Addr: mr.Addr()}), time.Hour, bytes.Repeat([]byte{9}, KeyLen))
	require.NoError(t, err)
	otherName := other.redisKey(convKey)
	sealed, err := mr.Get(name)
	require.NoError(t, err)
	require.NoError(t, mr.Set(otherName, sealed))
	_, err = other.Load(ctx, convKey)
	assert.Error(t, err, "a buffer sealed under another key must not open")
}

func TestNew_RequiresAFullKey(t *testing.T) {
	t.Parallel()
	_, err := New(nil, time.Hour, []byte("short"))
	assert.ErrorIs(t, err, ErrInvalidKey)
}

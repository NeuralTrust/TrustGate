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

package session_test

import (
	"context"
	"testing"
	"time"

	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/session"
	sessionrepo "github.com/NeuralTrust/AgentGateway/pkg/infra/repository/session"
	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newRepo(t *testing.T) (domain.Repository, *miniredis.Miniredis, *redis.Client) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return sessionrepo.NewRepository(rdb), mr, rdb
}

func TestRepository_SaveAndGet(t *testing.T) {
	repo, _, _ := newRepo(t)
	ctx := context.Background()

	sess := &domain.Session{
		ID:         "sess-1",
		GatewayID:  "gw-1",
		LastTurnID: "resp_123",
		Provider:   "openai",
		Model:      "gpt-4o",
		ExpiresAt:  time.Now().Add(time.Hour),
	}
	require.NoError(t, repo.Save(ctx, sess))

	got, err := repo.Get(ctx, "gw-1", "sess-1")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "resp_123", got.LastTurnID)
	assert.Equal(t, "openai", got.Provider)
	assert.Equal(t, "gpt-4o", got.Model)
}

func TestRepository_GetMissReturnsNil(t *testing.T) {
	repo, _, _ := newRepo(t)
	got, err := repo.Get(context.Background(), "gw-1", "absent")
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestRepository_NamespacedByGateway(t *testing.T) {
	repo, _, _ := newRepo(t)
	ctx := context.Background()
	require.NoError(t, repo.Save(ctx, &domain.Session{ID: "shared", GatewayID: "gw-a", LastTurnID: "resp_a", ExpiresAt: time.Now().Add(time.Hour)}))
	require.NoError(t, repo.Save(ctx, &domain.Session{ID: "shared", GatewayID: "gw-b", LastTurnID: "resp_b", ExpiresAt: time.Now().Add(time.Hour)}))

	a, err := repo.Get(ctx, "gw-a", "shared")
	require.NoError(t, err)
	require.NotNil(t, a)
	assert.Equal(t, "resp_a", a.LastTurnID)

	b, err := repo.Get(ctx, "gw-b", "shared")
	require.NoError(t, err)
	require.NotNil(t, b)
	assert.Equal(t, "resp_b", b.LastTurnID)
}

func TestRepository_TTLIsApplied(t *testing.T) {
	repo, mr, _ := newRepo(t)
	ctx := context.Background()
	require.NoError(t, repo.Save(ctx, &domain.Session{ID: "sess-ttl", GatewayID: "gw-1", LastTurnID: "resp_x", ExpiresAt: time.Now().Add(30 * time.Minute)}))

	ttl := mr.TTL("session:gw-1:sess-ttl")
	assert.Greater(t, ttl, time.Duration(0), "an eviction horizon must be set on the key")

	mr.FastForward(31 * time.Minute)
	got, err := repo.Get(ctx, "gw-1", "sess-ttl")
	require.NoError(t, err)
	assert.Nil(t, got, "entry must be evicted after its TTL elapses")
}

func TestRepository_SaveValidatesRequiredFields(t *testing.T) {
	repo, _, _ := newRepo(t)
	ctx := context.Background()
	assert.Error(t, repo.Save(ctx, nil))
	assert.Error(t, repo.Save(ctx, &domain.Session{ID: "", GatewayID: "gw-1"}))
	assert.Error(t, repo.Save(ctx, &domain.Session{ID: "sess-1", GatewayID: ""}))
}

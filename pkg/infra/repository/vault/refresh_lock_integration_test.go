//go:build integration

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

package vault_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	vaultrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/vault"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

func TestPostgresRefreshLockSerializesAndReleases(t *testing.T) {
	url := os.Getenv("TRUSTGATE_TEST_POSTGRES_URL")
	if url == "" {
		t.Skip("TRUSTGATE_TEST_POSTGRES_URL is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cfg, err := pgxpool.ParseConfig(url)
	require.NoError(t, err)
	cfg.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	defer pool.Close()
	repo := vaultrepo.NewRepository(&database.Connection{Pool: pool}, nil)
	gw := ids.New[ids.GatewayKind]()
	release, err := repo.AcquireRefreshLock(ctx, gw, "alice", "provider")
	require.NoError(t, err)
	released := false
	defer func() {
		if !released {
			require.NoError(t, release(ctx))
		}
	}()
	require.NoError(t, pool.Ping(ctx), "refresh must leave pool capacity available to Find and Upsert")
	peer := vaultrepo.NewRepository(&database.Connection{Pool: pool}, nil)
	waiterCtx, stop := context.WithTimeout(ctx, 50*time.Millisecond)
	defer stop()
	_, err = peer.AcquireRefreshLock(waiterCtx, gw, "alice", "provider")
	require.True(t, errors.Is(err, context.DeadlineExceeded), "waiting caller must honor deadline: %v", err)
	otherRelease, err := peer.AcquireRefreshLock(ctx, gw, "bob", "provider")
	require.NoError(t, err)
	require.NoError(t, otherRelease(ctx))
	require.NoError(t, release(ctx))
	released = true
	nextRelease, err := repo.AcquireRefreshLock(ctx, gw, "alice", "provider")
	require.NoError(t, err)
	require.NoError(t, nextRelease(ctx))
}

func TestPostgresRefreshLockBoundsDedicatedSessions(t *testing.T) {
	url := os.Getenv("TRUSTGATE_TEST_POSTGRES_URL")
	if url == "" {
		t.Skip("TRUSTGATE_TEST_POSTGRES_URL is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cfg, err := pgxpool.ParseConfig(url)
	require.NoError(t, err)
	cfg.MaxConns = 2
	appName := "refresh-budget-" + ids.New[ids.GatewayKind]().String()
	cfg.ConnConfig.RuntimeParams["application_name"] = appName
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	defer pool.Close()
	observer, err := pgx.Connect(ctx, url)
	require.NoError(t, err)
	defer func() { require.NoError(t, observer.Close(ctx)) }()
	repo := vaultrepo.NewRepository(&database.Connection{Pool: pool}, nil)
	gw := ids.New[ids.GatewayKind]()
	first, err := repo.AcquireRefreshLock(ctx, gw, "first", "provider")
	require.NoError(t, err)
	defer func() { require.NoError(t, first(ctx)) }()
	second, err := repo.AcquireRefreshLock(ctx, gw, "second", "provider")
	require.NoError(t, err)
	defer func() { require.NoError(t, second(ctx)) }()
	require.NoError(t, pool.Ping(ctx))
	results := make(chan error, 12)
	for i := range 12 {
		go func() {
			waitCtx, stop := context.WithTimeout(ctx, 200*time.Millisecond)
			defer stop()
			release, err := repo.AcquireRefreshLock(waitCtx, gw, fmt.Sprint("waiter-", i), "provider")
			if release != nil {
				err = errors.Join(errors.New("exceeded session budget"), release(ctx))
			}
			results <- err
		}()
	}
	require.Never(t, func() bool {
		var sessions int
		err := observer.QueryRow(ctx, "SELECT count(*) FROM pg_stat_activity WHERE application_name=$1", appName).Scan(&sessions)
		require.NoError(t, err)
		return sessions > 3
	}, 150*time.Millisecond, 10*time.Millisecond, "two dedicated sessions plus one reusable pool session is the limit")
	for range 12 {
		require.ErrorIs(t, <-results, context.DeadlineExceeded)
	}
	require.NoError(t, first(ctx))
	next, err := repo.AcquireRefreshLock(ctx, gw, "next", "provider")
	require.NoError(t, err)
	require.NoError(t, next(ctx))
}

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

package gateway_test

import (
	"context"
	"errors"
	"testing"
	"time"

	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	repomocks "github.com/NeuralTrust/TrustGate/pkg/domain/gateway/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/stretchr/testify/mock"
)

// BenchmarkFinder_CachedLookup measures a gateway served from memory. The
// lookup runs on every proxied, MCP and admin request, so its cost per hit is
// what a change to the finder must not grow.
func BenchmarkFinder_CachedLookup(b *testing.B) {
	id := ids.New[ids.GatewayKind]()
	now := time.Now().UTC()
	g := domain.Rehydrate(id, "prod", "active", "", nil, nil, nil, now, now)
	mgr := cache.NewTTLMapManager(time.Hour)
	mgr.GetTTLMap(cache.GatewayTTLName).Set("id:"+id.String(), g)
	mgr.GetTTLMap(cache.GatewayTTLName).Set("slug:prod", g)
	finder := appgateway.NewFinder(repomocks.NewRepository(b), mgr, newTestLogger())
	ctx := context.Background()

	b.Run("by_id", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := finder.FindByID(ctx, id); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("by_slug", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := finder.FindBySlug(ctx, "prod"); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkFinder_RememberedMiss measures an unknown gateway answered from the
// miss map, without a repository query.
func BenchmarkFinder_RememberedMiss(b *testing.B) {
	id := ids.New[ids.GatewayKind]()
	repo := repomocks.NewRepository(b)
	repo.EXPECT().FindByID(mock.Anything, id).Return(nil, domain.ErrNotFound).Once()
	repo.EXPECT().FindBySlug(mock.Anything, "ghost").Return(nil, domain.ErrNotFound).Once()
	mgr := cache.NewTTLMapManager(time.Hour)
	finder := appgateway.NewFinder(repo, mgr, newTestLogger())
	ctx := context.Background()
	_, _ = finder.FindByID(ctx, id)        // remembers the miss; the error is the expected not found
	_, _ = finder.FindBySlug(ctx, "ghost") // same

	b.Run("by_id", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := finder.FindByID(ctx, id); !errors.Is(err, domain.ErrNotFound) {
				b.Fatal(err)
			}
		}
	})
	b.Run("by_slug", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := finder.FindBySlug(ctx, "ghost"); !errors.Is(err, domain.ErrNotFound) {
				b.Fatal(err)
			}
		}
	})
}

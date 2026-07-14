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

package loadbalancer_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	cachemocks "github.com/NeuralTrust/TrustGate/pkg/infra/cache/mocks"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/loadbalancer"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/google/uuid"
)

func newBackend(t *testing.T, name string) *registry.Registry {
	t.Helper()
	b, err := registry.NewLLMRegistry(
		ids.New[ids.GatewayKind](),
		name,
		"",
		&registry.LLMTarget{Provider: "openai", Auth: registry.NewAPIKeyAuth("sk-1")},
	)
	if err != nil {
		t.Fatalf("NewLLMRegistry error: %v", err)
	}
	return b
}

func TestLoadBalancer_NextBackend_SkipsUnhealthyViaMGet(t *testing.T) {
	t.Parallel()

	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	cacheClient := cachemocks.NewClient(t)
	cacheClient.EXPECT().RedisClient().Return(rdb).Maybe()

	unhealthy := newBackend(t, "unhealthy")
	healthy := newBackend(t, "healthy")

	if err := mr.Set(fmt.Sprintf("lb:health:%s", unhealthy.ID.String()), `{"Healthy":false}`); err != nil {
		t.Fatalf("seed unhealthy status: %v", err)
	}

	lb, err := loadbalancer.NewLoadBalancer(loadbalancer.NewBaseFactory(nil, nil), loadbalancer.Pool{
		ID:         uuid.New().String(),
		Registries: []*registry.Registry{unhealthy, healthy},
		Algorithm:  loadbalancer.AlgorithmRoundRobin,
	}, newTestLogger(), cacheClient)
	if err != nil {
		t.Fatalf("NewLoadBalancer error: %v", err)
	}
	t.Cleanup(lb.Close)

	req := &infracontext.RequestContext{}
	for i := 0; i < 4; i++ {
		got, nerr := lb.NextBackend(context.Background(), req, nil)
		if nerr != nil {
			t.Fatalf("NextBackend error: %v", nerr)
		}
		if got.ID != healthy.ID {
			t.Fatalf("NextBackend returned %q, want the healthy backend", got.Name)
		}
	}
}

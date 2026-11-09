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
	"io"
	"log/slog"
	"testing"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	policydomain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
)

type benchmarkConsumerReader struct {
	domain.Reader
	consumers []*domain.Consumer
}

func (r benchmarkConsumerReader) ListByGateway(context.Context, ids.GatewayID) ([]*domain.Consumer, error) {
	return r.consumers, nil
}

type benchmarkPolicyRepository struct{ policydomain.Repository }

func (benchmarkPolicyRepository) ListByGateway(context.Context, ids.GatewayID) ([]*policydomain.Policy, error) {
	return nil, nil
}

func BenchmarkDataFinder(b *testing.B) {
	for _, size := range []int{1, 100, 1000} {
		b.Run(fmt.Sprintf("consumers=%d", size), func(b *testing.B) {
			gatewayID := ids.New[ids.GatewayKind]()
			consumers := make([]*domain.Consumer, size)
			for i := range consumers {
				consumers[i] = routableConsumer(gatewayID, nil)
				consumers[i].RegistryIDs = nil
			}
			for _, mode := range []string{"hit", "parallel_hit", "miss"} {
				b.Run(mode, func(b *testing.B) {
					manager := cache.NewTTLMapManager(time.Hour)
					finder := appconsumer.NewDataFinder(benchmarkConsumerReader{consumers: consumers}, nil, benchmarkPolicyRepository{}, nil, nil, manager, slog.New(slog.NewTextHandler(io.Discard, nil)))
					ctx := context.Background()
					if _, err := finder.FindByGateway(ctx, gatewayID); err != nil {
						b.Fatal(err)
					}
					b.ReportAllocs()
					b.ResetTimer()
					if mode == "parallel_hit" {
						b.RunParallel(func(pb *testing.PB) {
							for pb.Next() {
								if _, err := finder.FindByGateway(ctx, gatewayID); err != nil {
									b.Error(err)
								}
							}
						})
						return
					}
					for b.Loop() {
						if mode == "miss" {
							manager.ClearAllTTLMaps()
						}
						if _, err := finder.FindByGateway(ctx, gatewayID); err != nil {
							b.Fatal(err)
						}
					}
				})
			}
		})
	}
}

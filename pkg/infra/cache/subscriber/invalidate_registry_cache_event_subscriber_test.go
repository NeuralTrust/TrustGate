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

package subscriber_test

import (
	"context"
	"testing"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache/event"
	cachemocks "github.com/NeuralTrust/AgentGateway/pkg/infra/cache/mocks"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache/subscriber"
)

func TestInvalidateRegistryCacheEventSubscriber_OnEvent_EvictsRegistryDataAndGatewayBalancers(t *testing.T) {
	t.Parallel()
	gatewayID := "gw-1"
	otherGateway := "gw-2"
	backendID := "be-1"
	otherRegistryID := "be-2"

	backendMap := cache.NewTTLMap(cache.RegistryCacheTTL)
	consumerMap := cache.NewTTLMap(cache.ConsumerCacheTTL)
	consumerDataMap := cache.NewTTLMap(cache.ConsumerDataCacheTTL)
	loadBalancerMap := cache.NewTTLMap(cache.LoadBalancerCacheTTL)
	backendMap.Set(backendID, "backend")
	backendMap.Set(otherRegistryID, "keep")
	consumerMap.Set("consumer-1", "entity")
	consumerDataMap.Set(gatewayID, "aggregate")
	consumerDataMap.Set(otherGateway, "keep")
	loadBalancerMap.Set(gatewayID+":consumer-1", "lb")
	loadBalancerMap.Set(otherGateway+":consumer-9", "keep")

	client := cachemocks.NewClient(t)
	client.EXPECT().GetTTLMap(cache.RegistryTTLName).Return(backendMap).Once()
	client.EXPECT().GetTTLMap(cache.ConsumerTTLName).Return(consumerMap).Once()
	client.EXPECT().GetTTLMap(cache.ConsumerDataTTLName).Return(consumerDataMap).Once()
	client.EXPECT().GetTTLMap(cache.LoadBalancerTTLName).Return(loadBalancerMap).Once()

	sub := subscriber.NewInvalidateRegistryCacheEventSubscriber(discardLogger(), client)
	evt := event.InvalidateRegistryCacheEvent{GatewayID: gatewayID, RegistryID: backendID}
	if err := sub.OnEvent(context.Background(), evt); err != nil {
		t.Fatalf("OnEvent error: %v", err)
	}

	if _, ok := backendMap.Get(backendID); ok {
		t.Fatal("backend entry was not evicted")
	}
	if _, ok := consumerMap.Get("consumer-1"); ok {
		t.Fatal("consumer entity cache was not flushed; it may hold stale registry bindings")
	}
	if _, ok := consumerDataMap.Get(gatewayID); ok {
		t.Fatal("consumer-data entry for the gateway was not evicted")
	}
	if _, ok := loadBalancerMap.Get(gatewayID + ":consumer-1"); ok {
		t.Fatal("gateway-scoped load balancer entry was not evicted")
	}
	if _, ok := backendMap.Get(otherRegistryID); !ok {
		t.Fatal("unrelated backend entry must be preserved")
	}
	if _, ok := consumerDataMap.Get(otherGateway); !ok {
		t.Fatal("unrelated consumer-data entry must be preserved")
	}
	if _, ok := loadBalancerMap.Get(otherGateway + ":consumer-9"); !ok {
		t.Fatal("unrelated load balancer entry must be preserved")
	}
}

package subscriber_test

import (
	"context"
	"testing"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache/event"
	cachemocks "github.com/NeuralTrust/AgentGateway/pkg/infra/cache/mocks"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache/subscriber"
)

func TestInvalidateBackendCacheEventSubscriber_OnEvent_EvictsBackendDataAndGatewayBalancers(t *testing.T) {
	t.Parallel()
	gatewayID := "gw-1"
	otherGateway := "gw-2"
	backendID := "be-1"
	otherBackendID := "be-2"

	backendMap := cache.NewTTLMap(cache.BackendCacheTTL)
	consumerDataMap := cache.NewTTLMap(cache.ConsumerDataCacheTTL)
	loadBalancerMap := cache.NewTTLMap(cache.LoadBalancerCacheTTL)
	backendMap.Set(backendID, "backend")
	backendMap.Set(otherBackendID, "keep")
	consumerDataMap.Set(gatewayID, "aggregate")
	consumerDataMap.Set(otherGateway, "keep")
	loadBalancerMap.Set(gatewayID+":consumer-1", "lb")
	loadBalancerMap.Set(otherGateway+":consumer-9", "keep")

	client := cachemocks.NewClient(t)
	client.EXPECT().GetTTLMap(cache.BackendTTLName).Return(backendMap).Once()
	client.EXPECT().GetTTLMap(cache.ConsumerDataTTLName).Return(consumerDataMap).Once()
	client.EXPECT().GetTTLMap(cache.LoadBalancerTTLName).Return(loadBalancerMap).Once()

	sub := subscriber.NewInvalidateBackendCacheEventSubscriber(discardLogger(), client)
	evt := event.InvalidateBackendCacheEvent{GatewayID: gatewayID, BackendID: backendID}
	if err := sub.OnEvent(context.Background(), evt); err != nil {
		t.Fatalf("OnEvent error: %v", err)
	}

	if _, ok := backendMap.Get(backendID); ok {
		t.Fatal("backend entry was not evicted")
	}
	if _, ok := consumerDataMap.Get(gatewayID); ok {
		t.Fatal("consumer-data entry for the gateway was not evicted")
	}
	if _, ok := loadBalancerMap.Get(gatewayID + ":consumer-1"); ok {
		t.Fatal("gateway-scoped load balancer entry was not evicted")
	}
	if _, ok := backendMap.Get(otherBackendID); !ok {
		t.Fatal("unrelated backend entry must be preserved")
	}
	if _, ok := consumerDataMap.Get(otherGateway); !ok {
		t.Fatal("unrelated consumer-data entry must be preserved")
	}
	if _, ok := loadBalancerMap.Get(otherGateway + ":consumer-9"); !ok {
		t.Fatal("unrelated load balancer entry must be preserved")
	}
}

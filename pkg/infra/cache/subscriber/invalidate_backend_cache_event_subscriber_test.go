package subscriber_test

import (
	"context"
	"testing"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache/event"
	cachemocks "github.com/NeuralTrust/AgentGateway/pkg/infra/cache/mocks"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache/subscriber"
)

func TestInvalidateBackendCacheEventSubscriber_OnEvent_EvictsBackendAndLoadBalancer(t *testing.T) {
	t.Parallel()
	backendID := "be-1"
	otherID := "be-2"

	backendMap := cache.NewTTLMap(cache.BackendCacheTTL)
	loadBalancerMap := cache.NewTTLMap(cache.LoadBalancerCacheTTL)
	backendMap.Set(backendID, "backend")
	backendMap.Set(otherID, "keep")
	loadBalancerMap.Set(backendID, "lb")
	loadBalancerMap.Set(otherID, "keep")

	client := cachemocks.NewClient(t)
	client.EXPECT().GetTTLMap(cache.BackendTTLName).Return(backendMap).Once()
	client.EXPECT().GetTTLMap(cache.LoadBalancerTTLName).Return(loadBalancerMap).Once()

	sub := subscriber.NewInvalidateBackendCacheEventSubscriber(discardLogger(), client)
	evt := event.InvalidateBackendCacheEvent{GatewayID: "gw-1", BackendID: backendID}
	if err := sub.OnEvent(context.Background(), evt); err != nil {
		t.Fatalf("OnEvent error: %v", err)
	}

	if _, ok := backendMap.Get(backendID); ok {
		t.Fatal("backend entry was not evicted")
	}
	if _, ok := loadBalancerMap.Get(backendID); ok {
		t.Fatal("load balancer entry was not evicted")
	}
	if _, ok := backendMap.Get(otherID); !ok {
		t.Fatal("unrelated backend entry must be preserved")
	}
	if _, ok := loadBalancerMap.Get(otherID); !ok {
		t.Fatal("unrelated load balancer entry must be preserved")
	}
}

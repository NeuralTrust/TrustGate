package subscriber_test

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache/event"
	cachemocks "github.com/NeuralTrust/AgentGateway/pkg/infra/cache/mocks"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache/subscriber"
	"github.com/stretchr/testify/mock"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestInvalidateGatewayDataEventSubscriber_OnEvent_EvictsGatewayScopedEntries(t *testing.T) {
	t.Parallel()
	gatewayID := "gw-1"
	otherID := "gw-2"

	gatewayMap := cache.NewTTLMap(cache.GatewayCacheTTL)
	consumerDataMap := cache.NewTTLMap(cache.ConsumerDataCacheTTL)
	loadBalancerMap := cache.NewTTLMap(cache.LoadBalancerCacheTTL)
	gatewayMap.Set(gatewayID, "gateway")
	gatewayMap.Set(otherID, "keep")
	consumerDataMap.Set(gatewayID, "aggregate")
	consumerDataMap.Set(otherID, "keep")
	loadBalancerMap.Set(gatewayID+":consumer-1", "lb")
	loadBalancerMap.Set(otherID+":consumer-9", "keep")

	client := cachemocks.NewClient(t)
	client.EXPECT().GetTTLMap(cache.GatewayTTLName).Return(gatewayMap).Once()
	client.EXPECT().GetTTLMap(cache.ConsumerDataTTLName).Return(consumerDataMap).Once()
	client.EXPECT().GetTTLMap(cache.LoadBalancerTTLName).Return(loadBalancerMap).Once()
	client.EXPECT().DeleteAllByGatewayID(mock.Anything, gatewayID).Return(nil).Once()

	sub := subscriber.NewInvalidateGatewayDataEventSubscriber(discardLogger(), client)
	if err := sub.OnEvent(context.Background(), event.InvalidateGatewayDataEvent{GatewayID: gatewayID}); err != nil {
		t.Fatalf("OnEvent error: %v", err)
	}

	if _, ok := gatewayMap.Get(gatewayID); ok {
		t.Fatal("gateway entry was not evicted")
	}
	if _, ok := consumerDataMap.Get(gatewayID); ok {
		t.Fatal("consumer-data entry was not evicted")
	}
	if _, ok := loadBalancerMap.Get(gatewayID + ":consumer-1"); ok {
		t.Fatal("gateway-scoped load balancer entry was not evicted")
	}
	if _, ok := gatewayMap.Get(otherID); !ok {
		t.Fatal("unrelated gateway entry must be preserved")
	}
	if _, ok := consumerDataMap.Get(otherID); !ok {
		t.Fatal("unrelated consumer-data entry must be preserved")
	}
	if _, ok := loadBalancerMap.Get(otherID + ":consumer-9"); !ok {
		t.Fatal("unrelated load balancer entry must be preserved")
	}
}

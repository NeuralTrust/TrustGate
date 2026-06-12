package subscriber_test

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	gatewaydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/gateway"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
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
	id := ids.New[ids.GatewayKind]()
	gatewayID := id.String()
	otherID := ids.New[ids.GatewayKind]().String()
	now := time.Now().UTC()
	gw := gatewaydomain.RehydrateWithSlug(id, "Gateway", "acme", "active", nil, nil, nil, now, now)

	gatewayMap := cache.NewTTLMap(cache.GatewayCacheTTL)
	consumerMap := cache.NewTTLMap(cache.ConsumerCacheTTL)
	consumerDataMap := cache.NewTTLMap(cache.ConsumerDataCacheTTL)
	loadBalancerMap := cache.NewTTLMap(cache.LoadBalancerCacheTTL)
	authMap := cache.NewTTLMap(cache.AuthCacheTTL)
	consumerPathMap := cache.NewTTLMap(cache.ConsumerDataCacheTTL)
	roleMap := cache.NewTTLMap(cache.RoleCacheTTL)
	gatewayMap.Set("id:"+gatewayID, gw)
	gatewayMap.Set("slug:acme", gw)
	gatewayMap.Set("id:"+otherID, "keep")
	consumerMap.Set("consumer-1", "entity")
	consumerDataMap.Set(gatewayID, "aggregate")
	consumerDataMap.Set(otherID, "keep")
	loadBalancerMap.Set(gatewayID+":consumer-1", "lb")
	loadBalancerMap.Set(otherID+":consumer-9", "keep")
	authMap.Set("enabled:oauth2", "candidate-list")
	consumerPathMap.Set("|/v1/mcp/linear", "path-match")
	roleID := ids.New[ids.RoleKind]().String()
	roleMap.Set(roleID, "role")

	client := cachemocks.NewClient(t)
	client.EXPECT().GetTTLMap(cache.GatewayTTLName).Return(gatewayMap).Once()
	client.EXPECT().GetTTLMap(cache.ConsumerTTLName).Return(consumerMap).Once()
	client.EXPECT().GetTTLMap(cache.ConsumerDataTTLName).Return(consumerDataMap).Once()
	client.EXPECT().GetTTLMap(cache.LoadBalancerTTLName).Return(loadBalancerMap).Once()
	client.EXPECT().GetTTLMap(cache.AuthTTLName).Return(authMap).Once()
	client.EXPECT().GetTTLMap(cache.ConsumerPathTTLName).Return(consumerPathMap).Once()
	client.EXPECT().GetTTLMap(cache.RoleTTLName).Return(roleMap).Once()
	client.EXPECT().DeleteAllByGatewayID(mock.Anything, gatewayID).Return(nil).Once()

	sub := subscriber.NewInvalidateGatewayDataEventSubscriber(discardLogger(), client)
	if err := sub.OnEvent(context.Background(), event.InvalidateGatewayDataEvent{GatewayID: gatewayID}); err != nil {
		t.Fatalf("OnEvent error: %v", err)
	}

	if _, ok := gatewayMap.Get("id:" + gatewayID); ok {
		t.Fatal("gateway id alias was not evicted")
	}
	if _, ok := gatewayMap.Get("slug:acme"); ok {
		t.Fatal("gateway slug alias was not evicted")
	}
	if _, ok := consumerMap.Get("consumer-1"); ok {
		t.Fatal("consumer entity cache was not flushed; it may hold stale auth bindings")
	}
	if _, ok := consumerDataMap.Get(gatewayID); ok {
		t.Fatal("consumer-data entry was not evicted")
	}
	if _, ok := loadBalancerMap.Get(gatewayID + ":consumer-1"); ok {
		t.Fatal("gateway-scoped load balancer entry was not evicted")
	}
	if _, ok := roleMap.Get(roleID); ok {
		t.Fatal("role entry was not evicted")
	}
	if _, ok := gatewayMap.Get("id:" + otherID); !ok {
		t.Fatal("unrelated gateway entry must be preserved")
	}
	if _, ok := consumerDataMap.Get(otherID); !ok {
		t.Fatal("unrelated consumer-data entry must be preserved")
	}
	if _, ok := loadBalancerMap.Get(otherID + ":consumer-9"); !ok {
		t.Fatal("unrelated load balancer entry must be preserved")
	}
	if _, ok := authMap.Get("enabled:oauth2"); ok {
		t.Fatal("auth credential candidate list was not evicted")
	}
	if _, ok := consumerPathMap.Get("|/v1/mcp/linear"); ok {
		t.Fatal("consumer-path entry was not evicted")
	}
}

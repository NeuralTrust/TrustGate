package loadbalancer_test

import (
	"io"
	"log/slog"
	"testing"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/backend"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	cachemocks "github.com/NeuralTrust/AgentGateway/pkg/infra/cache/mocks"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/loadbalancer"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
)

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestLoadBalancer_Close_IdempotentAndSafe(t *testing.T) {
	t.Parallel()

	cacheClient := cachemocks.NewClient(t)
	cacheClient.EXPECT().
		Set(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(nil).
		Maybe()
	// A report buffered before Close may still be drained by the goroutine before
	// it observes done; performSuccessUpdate bails out on a nil client.
	cacheClient.EXPECT().RedisClient().Return(nil).Maybe()

	bk, err := backend.NewBackend(
		ids.New[ids.GatewayKind](),
		"backend-1",
		"openai",
		nil,
		"",
		1,
		backend.NewAPIKeyAuth("sk-1"),
		nil,
	)
	if err != nil {
		t.Fatalf("NewBackend error: %v", err)
	}

	lb, err := loadbalancer.NewLoadBalancer(loadbalancer.NewBaseFactory(nil, nil), loadbalancer.Pool{
		ID:        uuid.New().String(),
		Backends:  []*backend.Backend{bk},
		Algorithm: loadbalancer.AlgorithmRoundRobin,
	}, newTestLogger(), cacheClient)
	if err != nil {
		t.Fatalf("NewLoadBalancer error: %v", err)
	}

	lb.Close()
	lb.Close() // second close must not panic on a closed channel

	// ReportSuccess after Close must stay safe: it never sends on a closed
	// channel, so it cannot panic even once the background goroutine is gone.
	for i := 0; i < 2000; i++ {
		lb.ReportSuccess(bk)
	}
}

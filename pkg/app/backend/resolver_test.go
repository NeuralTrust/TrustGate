package backend_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	appbackend "github.com/NeuralTrust/AgentGateway/pkg/app/backend"
	appbackendmocks "github.com/NeuralTrust/AgentGateway/pkg/app/backend/mocks"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/backend"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	cachemocks "github.com/NeuralTrust/AgentGateway/pkg/infra/cache/mocks"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/loadbalancer"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
)

func newCacheClientStub(t *testing.T) *cachemocks.Client {
	client := cachemocks.NewClient(t)
	client.EXPECT().
		Set(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(nil).
		Maybe()
	return client
}

func TestBackendResolver_GetOrCreateLoadBalancer_BuildsAndCaches(t *testing.T) {
	t.Parallel()
	bk, err := domain.NewBackend(uuid.New(), "pool", domain.AlgorithmRoundRobin, validTargets(), nil, nil)
	if err != nil {
		t.Fatalf("NewBackend error: %v", err)
	}

	finder := appbackendmocks.NewFinder(t)
	finder.EXPECT().FindByID(mock.Anything, bk.ID).Return(bk, nil).Once()

	resolver := appbackend.NewBackendResolver(
		finder, loadbalancer.NewBaseFactory(nil, nil), newCacheClientStub(t), newCacheManager(), newTestLogger(),
	)

	lb, err := resolver.GetOrCreateLoadBalancer(context.Background(), bk.ID)
	if err != nil {
		t.Fatalf("GetOrCreateLoadBalancer error: %v", err)
	}
	if lb == nil {
		t.Fatal("expected a load balancer instance")
	}

	// Second call must reuse the cached instance: FindByID is expected only once.
	again, err := resolver.GetOrCreateLoadBalancer(context.Background(), bk.ID)
	if err != nil {
		t.Fatalf("second GetOrCreateLoadBalancer error: %v", err)
	}
	if again != lb {
		t.Fatal("expected the cached load balancer to be returned on the second call")
	}
}

func TestBackendResolver_GetOrCreateLoadBalancer_RecoversFromCorruptCacheEntry(t *testing.T) {
	t.Parallel()
	bk, err := domain.NewBackend(uuid.New(), "pool", domain.AlgorithmRoundRobin, validTargets(), nil, nil)
	if err != nil {
		t.Fatalf("NewBackend error: %v", err)
	}

	mgr := newCacheManager()
	mgr.GetTTLMap(cache.LoadBalancerTTLName).Set(bk.ID.String(), "not-a-load-balancer")

	finder := appbackendmocks.NewFinder(t)
	finder.EXPECT().FindByID(mock.Anything, bk.ID).Return(bk, nil).Once()

	resolver := appbackend.NewBackendResolver(
		finder, loadbalancer.NewBaseFactory(nil, nil), newCacheClientStub(t), mgr, newTestLogger(),
	)

	lb, err := resolver.GetOrCreateLoadBalancer(context.Background(), bk.ID)
	if err != nil {
		t.Fatalf("GetOrCreateLoadBalancer error: %v", err)
	}
	if lb == nil {
		t.Fatal("expected a rebuilt load balancer instance")
	}
}

func TestBackendResolver_GetOrCreateLoadBalancer_SingleFlightOnConcurrentMiss(t *testing.T) {
	t.Parallel()
	bk, err := domain.NewBackend(uuid.New(), "pool", domain.AlgorithmRoundRobin, validTargets(), nil, nil)
	if err != nil {
		t.Fatalf("NewBackend error: %v", err)
	}

	finder := appbackendmocks.NewFinder(t)
	// .Once() is the assertion: concurrent misses must collapse into a single
	// build, so the backend is looked up (and a balancer created) exactly once.
	finder.EXPECT().FindByID(mock.Anything, bk.ID).
		Run(func(context.Context, uuid.UUID) { time.Sleep(10 * time.Millisecond) }).
		Return(bk, nil).
		Once()

	resolver := appbackend.NewBackendResolver(
		finder, loadbalancer.NewBaseFactory(nil, nil), newCacheClientStub(t), newCacheManager(), newTestLogger(),
	)

	const goroutines = 50
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		results []*loadbalancer.LoadBalancer
	)
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			lb, err := resolver.GetOrCreateLoadBalancer(context.Background(), bk.ID)
			if err != nil {
				t.Errorf("GetOrCreateLoadBalancer error: %v", err)
				return
			}
			mu.Lock()
			results = append(results, lb)
			mu.Unlock()
		}()
	}
	wg.Wait()

	if len(results) != goroutines {
		t.Fatalf("got %d results, want %d", len(results), goroutines)
	}
	for i, lb := range results {
		if lb == nil {
			t.Fatalf("result %d is nil", i)
		}
		if lb != results[0] {
			t.Fatal("concurrent callers received different load balancer instances")
		}
	}
}

func TestBackendResolver_GetOrCreateLoadBalancer_PropagatesFinderError(t *testing.T) {
	t.Parallel()
	id := uuid.New()
	finder := appbackendmocks.NewFinder(t)
	finder.EXPECT().FindByID(mock.Anything, id).Return(nil, domain.ErrNotFound).Once()

	resolver := appbackend.NewBackendResolver(
		finder, loadbalancer.NewBaseFactory(nil, nil), cachemocks.NewClient(t), newCacheManager(), newTestLogger(),
	)

	if _, err := resolver.GetOrCreateLoadBalancer(context.Background(), id); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

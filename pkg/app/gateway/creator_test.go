package gateway_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	appgateway "github.com/NeuralTrust/AgentGateway/pkg/app/gateway"
	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/gateway"
	repomocks "github.com/NeuralTrust/AgentGateway/pkg/domain/gateway/mocks"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/telemetry"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"github.com/stretchr/testify/mock"
)

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newCacheManager() *cache.TTLMapManager {
	return cache.NewTTLMapManager(time.Hour)
}

func TestCreator_Create_Success(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	tel := &telemetry.Telemetry{ExtraParams: map[string]string{"env": "prod"}}
	repo.EXPECT().
		Save(mock.Anything, mock.MatchedBy(func(g *domain.Gateway) bool {
			return g.Name == "Prod" &&
				g.Status == "active" &&
				g.Telemetry == tel
		})).
		Return(nil).
		Once()

	mgr := newCacheManager()
	creator := appgateway.NewCreator(repo, mgr, newTestLogger())

	g, err := creator.Create(context.Background(), appgateway.CreateInput{
		Name:      "Prod",
		Telemetry: tel,
	})
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
	if g.Name != "Prod" || g.Status != "active" {
		t.Fatalf("Create returned unexpected gateway: %+v", g)
	}

	cached, ok := mgr.GetTTLMap(cache.GatewayTTLName).Get(g.ID.String())
	if !ok {
		t.Fatal("created gateway was not pre-warmed in the cache")
	}
	if cached.(*domain.Gateway).ID != g.ID {
		t.Fatal("cached gateway ID mismatch")
	}
}

func TestCreator_Create_RejectsEmptyName(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	mgr := newCacheManager()
	creator := appgateway.NewCreator(repo, mgr, newTestLogger())

	_, err := creator.Create(context.Background(), appgateway.CreateInput{
		Name: "",
	})
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
}

func TestCreator_Create_PropagatesRepoError(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().
		Save(mock.Anything, mock.Anything).
		Return(domain.ErrAlreadyExists).
		Once()

	mgr := newCacheManager()
	creator := appgateway.NewCreator(repo, mgr, newTestLogger())

	_, err := creator.Create(context.Background(), appgateway.CreateInput{
		Name: "Prod",
	})
	if !errors.Is(err, domain.ErrAlreadyExists) {
		t.Fatalf("expected ErrAlreadyExists, got %v", err)
	}
	if !errors.Is(err, commonerrors.ErrAlreadyExists) {
		t.Fatalf("expected wrapped commonerrors.ErrAlreadyExists, got %v", err)
	}
}

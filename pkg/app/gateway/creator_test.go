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
	repo.EXPECT().
		Save(mock.Anything, mock.MatchedBy(func(g *domain.Gateway) bool {
			return g.Name == "Prod" && g.Description == "primary"
		})).
		Return(nil).
		Once()

	mgr := newCacheManager()
	creator := appgateway.NewCreator(repo, mgr, newTestLogger())

	g, err := creator.Create(context.Background(), appgateway.CreateInput{
		Name:        "Prod",
		Description: "primary",
	})
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
	if g.Name != "Prod" || g.Description != "primary" {
		t.Fatalf("Create returned unexpected gateway: %+v", g)
	}

	// Pre-warm: the cache should hold the new entity under its ID.
	cached, ok := mgr.GetTTLMap(cache.GatewayTTLName).Get(g.ID.String())
	if !ok {
		t.Fatal("created gateway was not pre-warmed in the cache")
	}
	if cached.(*domain.Gateway).ID != g.ID {
		t.Fatal("cached gateway ID mismatch")
	}
}

func TestCreator_Create_RejectsInvalidName(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	// repo.Save must never be called.
	mgr := newCacheManager()
	creator := appgateway.NewCreator(repo, mgr, newTestLogger())

	_, err := creator.Create(context.Background(), appgateway.CreateInput{
		Name:        "   ",
		Description: "",
	})
	if !errors.Is(err, commonerrors.ErrValidation) {
		t.Fatalf("expected validation error, got %v", err)
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
		Name:        "Prod",
		Description: "",
	})
	if !errors.Is(err, domain.ErrAlreadyExists) {
		t.Fatalf("expected ErrAlreadyExists, got %v", err)
	}
	if !errors.Is(err, commonerrors.ErrAlreadyExists) {
		t.Fatalf("expected wrapped commonerrors.ErrAlreadyExists, got %v", err)
	}
}

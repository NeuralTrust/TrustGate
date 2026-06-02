package auth_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	appauth "github.com/NeuralTrust/AgentGateway/pkg/app/auth"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
	repomocks "github.com/NeuralTrust/AgentGateway/pkg/domain/auth/mocks"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"github.com/stretchr/testify/mock"
)

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newCacheManager() *cache.TTLMapManager {
	return cache.NewTTLMapManager(time.Hour)
}

func validConfig() domain.Config {
	return domain.Config{APIKey: &domain.APIKeyConfig{Key: "super-secret-key"}}
}

func TestCreator_Create_Success(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	gwID := ids.New[ids.GatewayKind]()
	repo.EXPECT().
		Save(mock.Anything, mock.MatchedBy(func(a *domain.Auth) bool {
			return a.GatewayID == gwID && a.Name == "client-key" && a.Type == domain.TypeAPIKey
		})).
		Return(nil).
		Once()

	mgr := newCacheManager()
	creator := appauth.NewCreator(repo, mgr, newTestLogger())

	a, err := creator.Create(context.Background(), appauth.CreateInput{
		GatewayID: gwID,
		Name:      "client-key",
		Type:      domain.TypeAPIKey,
		Enabled:   true,
		Config:    validConfig(),
	})
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
	cached, ok := mgr.GetTTLMap(cache.AuthTTLName).Get(a.ID.String())
	if !ok {
		t.Fatal("created auth was not pre-warmed in the cache")
	}
	if cached.(*domain.Auth).ID != a.ID {
		t.Fatal("cached auth ID mismatch")
	}
}

func TestCreator_Create_RejectsInvalid(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	creator := appauth.NewCreator(repo, newCacheManager(), newTestLogger())

	_, err := creator.Create(context.Background(), appauth.CreateInput{
		GatewayID: ids.New[ids.GatewayKind](),
		Name:      "",
		Type:      domain.TypeAPIKey,
		Config:    validConfig(),
	})
	if !errors.Is(err, domain.ErrInvalidName) {
		t.Fatalf("err = %v, want ErrInvalidName", err)
	}
}

func TestCreator_Create_PropagatesRepoError(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().Save(mock.Anything, mock.Anything).Return(domain.ErrAlreadyExists).Once()
	creator := appauth.NewCreator(repo, newCacheManager(), newTestLogger())

	_, err := creator.Create(context.Background(), appauth.CreateInput{
		GatewayID: ids.New[ids.GatewayKind](),
		Name:      "dupe",
		Type:      domain.TypeAPIKey,
		Config:    validConfig(),
	})
	if !errors.Is(err, domain.ErrAlreadyExists) {
		t.Fatalf("err = %v, want ErrAlreadyExists", err)
	}
}

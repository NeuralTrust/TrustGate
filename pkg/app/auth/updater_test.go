package auth_test

import (
	"context"
	"errors"
	"testing"

	appauth "github.com/NeuralTrust/AgentGateway/pkg/app/auth"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
	repomocks "github.com/NeuralTrust/AgentGateway/pkg/domain/auth/mocks"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache/cachetest"
	"github.com/stretchr/testify/mock"
)

func ptr[T any](v T) *T { return &v }

func existingAuth(gwID ids.GatewayID) *domain.Auth {
	a, _ := domain.NewAuth(gwID, "current", domain.TypeAPIKey, true, validConfig())
	return a
}

func oauth2Config(clientSecret string) domain.Config {
	return domain.Config{
		OAuth2: &domain.OAuth2Config{
			Issuer:       "https://issuer.example.com",
			JWKSURL:      "https://issuer.example.com/jwks",
			ClientID:     "client-123",
			ClientSecret: clientSecret,
		},
	}
}

func existingOAuth2Auth(gwID ids.GatewayID) *domain.Auth {
	a, _ := domain.NewAuth(gwID, "oauth-cred", domain.TypeOAuth2, true, oauth2Config("real-secret"))
	return a
}

func TestUpdater_Update_Success(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	gwID := ids.New[ids.GatewayKind]()
	existing := existingAuth(gwID)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().
		Update(mock.Anything, mock.MatchedBy(func(a *domain.Auth) bool {
			return a.ID == existing.ID && a.Name == "renamed"
		})).
		Return(nil).
		Once()

	updater := appauth.NewUpdater(repo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
	got, err := updater.Update(context.Background(), appauth.UpdateInput{
		ID:        existing.ID,
		GatewayID: gwID,
		Name:      ptr("renamed"),
		Type:      ptr(domain.TypeAPIKey),
		Enabled:   ptr(true),
		Config:    ptr(validConfig()),
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if got.Name != "renamed" {
		t.Fatalf("expected renamed, got %s", got.Name)
	}
}

func TestUpdater_Update_Partial_PreservesTypeAndConfig(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	gwID := ids.New[ids.GatewayKind]()
	existing := existingOAuth2Auth(gwID)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().
		Update(mock.Anything, mock.MatchedBy(func(a *domain.Auth) bool {
			return a.Name == "renamed" && a.Type == domain.TypeOAuth2 &&
				a.Config.OAuth2 != nil && a.Config.OAuth2.ClientSecret == "real-secret"
		})).
		Return(nil).
		Once()

	updater := appauth.NewUpdater(repo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
	got, err := updater.Update(context.Background(), appauth.UpdateInput{
		ID:        existing.ID,
		GatewayID: gwID,
		Name:      ptr("renamed"),
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if got.Type != domain.TypeOAuth2 {
		t.Fatalf("Type = %q, want preserved oauth2", got.Type)
	}
	if got.Config.OAuth2 == nil || got.Config.OAuth2.ClientSecret != "real-secret" {
		t.Fatalf("oauth2 config not preserved: %+v", got.Config.OAuth2)
	}
}

func TestUpdater_Update_PreservesSecretWhenMasked(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	gwID := ids.New[ids.GatewayKind]()
	existing := existingOAuth2Auth(gwID)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().
		Update(mock.Anything, mock.MatchedBy(func(a *domain.Auth) bool {
			return a.Config.OAuth2 != nil && a.Config.OAuth2.ClientSecret == "real-secret"
		})).
		Return(nil).
		Once()

	updater := appauth.NewUpdater(repo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
	got, err := updater.Update(context.Background(), appauth.UpdateInput{
		ID:        existing.ID,
		GatewayID: gwID,
		Config:    ptr(oauth2Config("***")),
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if got.Config.OAuth2 == nil || got.Config.OAuth2.ClientSecret != "real-secret" {
		t.Fatalf("masked secret not resolved to stored value: %+v", got.Config.OAuth2)
	}
}

func TestUpdater_Update_GatewayMismatch(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	existing := existingAuth(ids.New[ids.GatewayKind]())
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()

	updater := appauth.NewUpdater(repo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
	_, err := updater.Update(context.Background(), appauth.UpdateInput{
		ID:        existing.ID,
		GatewayID: ids.New[ids.GatewayKind](),
		Name:      ptr("renamed"),
		Type:      ptr(domain.TypeAPIKey),
		Config:    ptr(validConfig()),
	})
	if !errors.Is(err, domain.ErrInvalidGatewayID) {
		t.Fatalf("err = %v, want ErrInvalidGatewayID", err)
	}
}

func TestUpdater_Update_NotFound(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := ids.New[ids.AuthKind]()
	repo.EXPECT().FindByID(mock.Anything, id).Return(nil, domain.ErrNotFound).Once()

	updater := appauth.NewUpdater(repo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
	_, err := updater.Update(context.Background(), appauth.UpdateInput{
		ID:     id,
		Name:   ptr("x"),
		Type:   ptr(domain.TypeAPIKey),
		Config: ptr(validConfig()),
	})
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

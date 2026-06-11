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

func enabledOAuth2(t *testing.T, issuer string, audiences ...string) *domain.Auth {
	t.Helper()
	a, err := domain.NewAuth(ids.New[ids.GatewayKind](), "idp", domain.TypeOAuth2, true, domain.Config{
		OAuth2: &domain.OAuth2Config{
			Issuer:    issuer,
			JWKSURL:   "https://idp.example.com/jwks",
			Audiences: audiences,
		},
	})
	if err != nil {
		t.Fatalf("NewAuth: %v", err)
	}
	return a
}

func createOAuth2(t *testing.T, repo *repomocks.Repository, audiences ...string) error {
	t.Helper()
	creator := appauth.NewCreator(repo, newCacheManager(), newTestLogger())
	_, err := creator.Create(context.Background(), appauth.CreateInput{
		GatewayID: ids.New[ids.GatewayKind](),
		Name:      "new-idp",
		Type:      domain.TypeOAuth2,
		Enabled:   true,
		Config: domain.Config{OAuth2: &domain.OAuth2Config{
			Issuer:    "https://idp.example.com",
			JWKSURL:   "https://idp.example.com/jwks",
			Audiences: audiences,
		}},
	})
	return err
}

func TestCreator_RejectsDuplicateIssuerAudience(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindEnabledByTypes(mock.Anything, []domain.Type{domain.TypeOAuth2}).
		Return([]*domain.Auth{enabledOAuth2(t, "https://idp.example.com", "api://abc")}, nil).Once()

	err := createOAuth2(t, repo, "api://abc")
	if !errors.Is(err, domain.ErrDuplicateOAuth2) {
		t.Fatalf("err = %v, want ErrDuplicateOAuth2", err)
	}
}

func TestCreator_RejectsAudienceEquivalence(t *testing.T) {
	t.Parallel()
	// api://{guid} (Entra v1) and the bare guid (v2) are the same audience.
	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindEnabledByTypes(mock.Anything, []domain.Type{domain.TypeOAuth2}).
		Return([]*domain.Auth{enabledOAuth2(t, "https://idp.example.com", "api://abc")}, nil).Once()

	err := createOAuth2(t, repo, "abc")
	if !errors.Is(err, domain.ErrDuplicateOAuth2) {
		t.Fatalf("err = %v, want ErrDuplicateOAuth2", err)
	}
}

func TestCreator_RejectsWildcardAudienceOverlap(t *testing.T) {
	t.Parallel()
	// An entry without audiences accepts any audience of its issuer.
	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindEnabledByTypes(mock.Anything, []domain.Type{domain.TypeOAuth2}).
		Return([]*domain.Auth{enabledOAuth2(t, "https://idp.example.com")}, nil).Once()

	err := createOAuth2(t, repo, "api://abc")
	if !errors.Is(err, domain.ErrDuplicateOAuth2) {
		t.Fatalf("err = %v, want ErrDuplicateOAuth2", err)
	}
}

func TestCreator_AllowsSameIssuerDistinctAudience(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindEnabledByTypes(mock.Anything, []domain.Type{domain.TypeOAuth2}).
		Return([]*domain.Auth{enabledOAuth2(t, "https://idp.example.com", "api://tenant-a")}, nil).Once()
	repo.EXPECT().Save(mock.Anything, mock.Anything).Return(nil).Once()

	if err := createOAuth2(t, repo, "api://tenant-b"); err != nil {
		t.Fatalf("expected same issuer with distinct audience to be allowed, got %v", err)
	}
}

func TestUpdater_RejectsEnablingConflictingAuth(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	existing := enabledOAuth2(t, "https://idp.example.com", "api://abc")
	existing.Enabled = false
	other := enabledOAuth2(t, "https://idp.example.com", "abc")

	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().FindEnabledByTypes(mock.Anything, []domain.Type{domain.TypeOAuth2}).
		Return([]*domain.Auth{other}, nil).Once()

	updater := appauth.NewUpdater(repo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
	_, err := updater.Update(context.Background(), appauth.UpdateInput{
		ID:      existing.ID,
		Enabled: ptr(true),
	})
	if !errors.Is(err, domain.ErrDuplicateOAuth2) {
		t.Fatalf("err = %v, want ErrDuplicateOAuth2", err)
	}
}

func TestUpdater_AllowsUpdatingSameEntry(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	existing := enabledOAuth2(t, "https://idp.example.com", "api://abc")

	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	// The candidate list contains the entry being updated: it must not
	// conflict with itself.
	repo.EXPECT().FindEnabledByTypes(mock.Anything, []domain.Type{domain.TypeOAuth2}).
		Return([]*domain.Auth{existing}, nil).Once()
	repo.EXPECT().Update(mock.Anything, mock.Anything).Return(nil).Once()

	updater := appauth.NewUpdater(repo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
	if _, err := updater.Update(context.Background(), appauth.UpdateInput{
		ID:   existing.ID,
		Name: ptr("renamed"),
	}); err != nil {
		t.Fatalf("expected self-update to pass the guardrail, got %v", err)
	}
}

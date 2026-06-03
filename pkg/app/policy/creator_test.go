package policy_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	pluginmocks "github.com/NeuralTrust/AgentGateway/pkg/app/plugins/mocks"
	apppolicy "github.com/NeuralTrust/AgentGateway/pkg/app/policy"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
	repomocks "github.com/NeuralTrust/AgentGateway/pkg/domain/policy/mocks"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"github.com/stretchr/testify/mock"
)

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newCacheManager() *cache.TTLMapManager {
	return cache.NewTTLMapManager(time.Hour)
}

// newRegistryMock returns a plugin registry mock whose ValidateStages yields
// stagesErr. It is marked Maybe() so tests where validation is never reached
// (e.g. domain validation fails first) do not fail on an unmet expectation.
func newRegistryMock(t *testing.T, stagesErr error) *pluginmocks.Registry {
	t.Helper()
	reg := pluginmocks.NewRegistry(t)
	reg.EXPECT().ValidateStages(mock.Anything, mock.Anything).Return(stagesErr).Maybe()
	reg.EXPECT().Validate(mock.Anything, mock.Anything).Return(nil).Maybe()
	return reg
}

func validCreateInput(gwID ids.GatewayID) apppolicy.CreateInput {
	return apppolicy.CreateInput{
		GatewayID: gwID,
		Name:      "default",
		Slug:      "rate_limiter",
		Enabled:   true,
		Settings:  map[string]any{"limit": 100},
	}
}

func TestCreator_Create_Success(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	gwID := ids.New[ids.GatewayKind]()
	repo.EXPECT().
		Save(mock.Anything, mock.MatchedBy(func(p *domain.Policy) bool {
			return p.GatewayID == gwID && p.Name == "default" && p.Slug == "rate_limiter" && !p.Global
		})).
		Return(nil).
		Once()

	mgr := newCacheManager()
	creator := apppolicy.NewCreator(repo, newRegistryMock(t, nil), mgr, newTestLogger())

	p, err := creator.Create(context.Background(), validCreateInput(gwID))
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
	cached, ok := mgr.GetTTLMap(cache.PolicyTTLName).Get(p.ID.String())
	if !ok {
		t.Fatal("created policy was not pre-warmed in the cache")
	}
	if cached.(*domain.Policy).ID != p.ID {
		t.Fatal("cached policy ID mismatch")
	}
}

func TestCreator_Create_RejectsInvalid(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	creator := apppolicy.NewCreator(repo, newRegistryMock(t, nil), newCacheManager(), newTestLogger())

	in := validCreateInput(ids.New[ids.GatewayKind]())
	in.Name = ""
	_, err := creator.Create(context.Background(), in)
	if !errors.Is(err, domain.ErrInvalidName) {
		t.Fatalf("err = %v, want ErrInvalidName", err)
	}
}

func TestCreator_Create_RejectsUnsupportedStage(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	sentinel := errors.New("stage not supported")
	creator := apppolicy.NewCreator(repo, newRegistryMock(t, sentinel), newCacheManager(), newTestLogger())

	_, err := creator.Create(context.Background(), validCreateInput(ids.New[ids.GatewayKind]()))
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want registry stage error", err)
	}
}

func TestCreator_Create_PropagatesRepoError(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().Save(mock.Anything, mock.Anything).Return(domain.ErrAlreadyExists).Once()
	creator := apppolicy.NewCreator(repo, newRegistryMock(t, nil), newCacheManager(), newTestLogger())

	in := validCreateInput(ids.New[ids.GatewayKind]())
	in.Name = "dupe"
	_, err := creator.Create(context.Background(), in)
	if !errors.Is(err, domain.ErrAlreadyExists) {
		t.Fatalf("err = %v, want ErrAlreadyExists", err)
	}
}

func TestCreator_Create_DefaultsToNonGlobal(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().Save(mock.Anything, mock.Anything).Return(nil).Once()
	creator := apppolicy.NewCreator(repo, newRegistryMock(t, nil), newCacheManager(), newTestLogger())

	p, err := creator.Create(context.Background(), validCreateInput(ids.New[ids.GatewayKind]()))
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
	if p.Global {
		t.Fatal("a freshly-created policy must not be global")
	}
}

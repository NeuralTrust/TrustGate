package policy_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	apppolicy "github.com/NeuralTrust/AgentGateway/pkg/app/policy"
	policymocks "github.com/NeuralTrust/AgentGateway/pkg/app/policy/mocks"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
	"github.com/stretchr/testify/mock"
)

func sourcePolicy(gwID ids.GatewayID, name string) *domain.Policy {
	return &domain.Policy{
		ID:          ids.New[ids.PolicyKind](),
		GatewayID:   gwID,
		ConsumerIDs: []ids.ConsumerID{ids.New[ids.ConsumerKind]()},
		Name:        name,
		Description: "rate limit policy",
		Slug:        "rate_limiter",
		Enabled:     true,
		Global:      true,
		Priority:    5,
		Parallel:    true,
		Settings:    map[string]any{"limit": 100},
		Stages:      []domain.Stage{domain.StagePreRequest},
	}
}

func createInputMatcher(want apppolicy.CreateInput) interface{} {
	return mock.MatchedBy(func(in apppolicy.CreateInput) bool {
		return in.GatewayID == want.GatewayID &&
			in.Name == want.Name &&
			in.Description == want.Description &&
			in.Slug == want.Slug &&
			in.Enabled == want.Enabled &&
			in.Priority == want.Priority &&
			in.Parallel == want.Parallel &&
			reflect.DeepEqual(in.Settings, want.Settings) &&
			reflect.DeepEqual(in.Stages, want.Stages)
	})
}

func createFromInput(_ context.Context, in apppolicy.CreateInput) (*domain.Policy, error) {
	return domain.NewPolicy(in.GatewayID, in.Name, in.Slug, in.Enabled, in.Priority, in.Parallel, in.Settings, in.Stages, in.Description)
}

func TestDuplicator_CopiesConfigWithFirstFreeSuffix(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	src := sourcePolicy(gwID, "Foo")

	finder := policymocks.NewFinder(t)
	finder.EXPECT().FindByID(mock.Anything, gwID, src.ID).Return(src, nil).Once()
	finder.EXPECT().
		List(mock.Anything, mock.MatchedBy(func(f domain.ListFilter) bool {
			return f.GatewayID == gwID && f.NameContains == "Foo"
		})).
		Return([]*domain.Policy{src}, 1, nil).
		Once()

	creator := policymocks.NewCreator(t)
	creator.EXPECT().
		Create(mock.Anything, createInputMatcher(apppolicy.CreateInput{
			GatewayID:   gwID,
			Name:        "Foo 2",
			Description: "rate limit policy",
			Slug:        "rate_limiter",
			Enabled:     true,
			Priority:    5,
			Parallel:    true,
			Settings:    map[string]any{"limit": 100},
			Stages:      []domain.Stage{domain.StagePreRequest},
		})).
		RunAndReturn(createFromInput).
		Once()

	dup := apppolicy.NewDuplicator(finder, creator, newTestLogger())
	got, err := dup.Duplicate(context.Background(), gwID, src.ID)
	if err != nil {
		t.Fatalf("Duplicate error: %v", err)
	}
	if got.Name != "Foo 2" {
		t.Fatalf("name = %q, want %q", got.Name, "Foo 2")
	}
	if got.ID == src.ID {
		t.Fatal("duplicate must have a fresh id")
	}
	if got.Global {
		t.Fatal("duplicate must not be global")
	}
	if len(got.ConsumerIDs) != 0 {
		t.Fatalf("duplicate must start with no consumers, got %d", len(got.ConsumerIDs))
	}
	if !reflect.DeepEqual(got.Settings, src.Settings) {
		t.Fatalf("settings = %v, want %v", got.Settings, src.Settings)
	}
	if !reflect.DeepEqual(got.Stages, src.Stages) {
		t.Fatalf("stages = %v, want %v", got.Stages, src.Stages)
	}
	if got.Description != src.Description {
		t.Fatalf("description = %q, want %q", got.Description, src.Description)
	}
}

func TestDuplicator_SkipsTakenSuffixes(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	src := sourcePolicy(gwID, "Foo")
	existing := []*domain.Policy{
		src,
		{ID: ids.New[ids.PolicyKind](), GatewayID: gwID, Name: "Foo 2"},
	}

	finder := policymocks.NewFinder(t)
	finder.EXPECT().FindByID(mock.Anything, gwID, src.ID).Return(src, nil).Once()
	finder.EXPECT().List(mock.Anything, mock.Anything).Return(existing, len(existing), nil).Once()

	creator := policymocks.NewCreator(t)
	creator.EXPECT().
		Create(mock.Anything, mock.MatchedBy(func(in apppolicy.CreateInput) bool {
			return in.Name == "Foo 3"
		})).
		RunAndReturn(createFromInput).
		Once()

	dup := apppolicy.NewDuplicator(finder, creator, newTestLogger())
	got, err := dup.Duplicate(context.Background(), gwID, src.ID)
	if err != nil {
		t.Fatalf("Duplicate error: %v", err)
	}
	if got.Name != "Foo 3" {
		t.Fatalf("name = %q, want %q", got.Name, "Foo 3")
	}
}

func TestDuplicator_StripsTrailingNumberFromSourceName(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	src := sourcePolicy(gwID, "Foo 2")
	existing := []*domain.Policy{
		{ID: ids.New[ids.PolicyKind](), GatewayID: gwID, Name: "Foo"},
		src,
	}

	finder := policymocks.NewFinder(t)
	finder.EXPECT().FindByID(mock.Anything, gwID, src.ID).Return(src, nil).Once()
	finder.EXPECT().
		List(mock.Anything, mock.MatchedBy(func(f domain.ListFilter) bool {
			return f.NameContains == "Foo"
		})).
		Return(existing, len(existing), nil).
		Once()

	creator := policymocks.NewCreator(t)
	creator.EXPECT().
		Create(mock.Anything, mock.MatchedBy(func(in apppolicy.CreateInput) bool {
			return in.Name == "Foo 3"
		})).
		RunAndReturn(createFromInput).
		Once()

	dup := apppolicy.NewDuplicator(finder, creator, newTestLogger())
	got, err := dup.Duplicate(context.Background(), gwID, src.ID)
	if err != nil {
		t.Fatalf("Duplicate error: %v", err)
	}
	if got.Name != "Foo 3" {
		t.Fatalf("name = %q, want %q (must not be 'Foo 2 2')", got.Name, "Foo 3")
	}
}

func TestDuplicator_RetriesOnNameConflict(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	src := sourcePolicy(gwID, "Foo")

	finder := policymocks.NewFinder(t)
	finder.EXPECT().FindByID(mock.Anything, gwID, src.ID).Return(src, nil).Once()
	finder.EXPECT().List(mock.Anything, mock.Anything).Return(nil, 0, nil).Once()

	creator := policymocks.NewCreator(t)
	creator.EXPECT().
		Create(mock.Anything, mock.MatchedBy(func(in apppolicy.CreateInput) bool {
			return in.Name == "Foo 2"
		})).
		Return(nil, domain.ErrAlreadyExists).
		Once()
	creator.EXPECT().
		Create(mock.Anything, mock.MatchedBy(func(in apppolicy.CreateInput) bool {
			return in.Name == "Foo 3"
		})).
		RunAndReturn(createFromInput).
		Once()

	dup := apppolicy.NewDuplicator(finder, creator, newTestLogger())
	got, err := dup.Duplicate(context.Background(), gwID, src.ID)
	if err != nil {
		t.Fatalf("Duplicate error: %v", err)
	}
	if got.Name != "Foo 3" {
		t.Fatalf("name = %q, want %q after conflict retry", got.Name, "Foo 3")
	}
}

func TestDuplicator_StartsAboveSourceNumber(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	src := sourcePolicy(gwID, "Policy 3")

	finder := policymocks.NewFinder(t)
	finder.EXPECT().FindByID(mock.Anything, gwID, src.ID).Return(src, nil).Once()
	finder.EXPECT().
		List(mock.Anything, mock.MatchedBy(func(f domain.ListFilter) bool {
			return f.NameContains == "Policy"
		})).
		Return([]*domain.Policy{src}, 1, nil).
		Once()

	creator := policymocks.NewCreator(t)
	creator.EXPECT().
		Create(mock.Anything, mock.MatchedBy(func(in apppolicy.CreateInput) bool {
			return in.Name == "Policy 4"
		})).
		RunAndReturn(createFromInput).
		Once()

	dup := apppolicy.NewDuplicator(finder, creator, newTestLogger())
	got, err := dup.Duplicate(context.Background(), gwID, src.ID)
	if err != nil {
		t.Fatalf("Duplicate error: %v", err)
	}
	if got.Name != "Policy 4" {
		t.Fatalf("name = %q, want %q (must never drop below the source number)", got.Name, "Policy 4")
	}
}

func TestDuplicator_DeepClonesSettings(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	src := sourcePolicy(gwID, "Foo")
	src.Settings = map[string]any{
		"limits": map[string]any{
			"global": map[string]any{"limit": 100},
		},
	}

	finder := policymocks.NewFinder(t)
	finder.EXPECT().FindByID(mock.Anything, gwID, src.ID).Return(src, nil).Once()
	finder.EXPECT().List(mock.Anything, mock.Anything).Return([]*domain.Policy{src}, 1, nil).Once()

	creator := policymocks.NewCreator(t)
	creator.EXPECT().Create(mock.Anything, mock.Anything).RunAndReturn(createFromInput).Once()

	dup := apppolicy.NewDuplicator(finder, creator, newTestLogger())
	got, err := dup.Duplicate(context.Background(), gwID, src.ID)
	if err != nil {
		t.Fatalf("Duplicate error: %v", err)
	}

	gotGlobal := got.Settings["limits"].(map[string]any)["global"].(map[string]any)
	gotGlobal["limit"] = 999

	srcGlobal := src.Settings["limits"].(map[string]any)["global"].(map[string]any)
	if srcGlobal["limit"] != 100 {
		t.Fatalf("mutating the duplicate's nested settings leaked into the source: got %v", srcGlobal["limit"])
	}
}

func TestDuplicator_PropagatesNotFound(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	id := ids.New[ids.PolicyKind]()

	finder := policymocks.NewFinder(t)
	finder.EXPECT().FindByID(mock.Anything, gwID, id).Return(nil, domain.ErrNotFound).Once()

	creator := policymocks.NewCreator(t)

	dup := apppolicy.NewDuplicator(finder, creator, newTestLogger())
	_, err := dup.Duplicate(context.Background(), gwID, id)
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestDuplicator_PropagatesNonConflictCreateError(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	src := sourcePolicy(gwID, "Foo")
	sentinel := errors.New("boom")

	finder := policymocks.NewFinder(t)
	finder.EXPECT().FindByID(mock.Anything, gwID, src.ID).Return(src, nil).Once()
	finder.EXPECT().List(mock.Anything, mock.Anything).Return(nil, 0, nil).Once()

	creator := policymocks.NewCreator(t)
	creator.EXPECT().Create(mock.Anything, mock.Anything).Return(nil, sentinel).Once()

	dup := apppolicy.NewDuplicator(finder, creator, newTestLogger())
	_, err := dup.Duplicate(context.Background(), gwID, src.ID)
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want sentinel", err)
	}
}

// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package consumer_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	apppolicy "github.com/NeuralTrust/TrustGate/pkg/app/policy"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	authmocks "github.com/NeuralTrust/TrustGate/pkg/domain/auth/mocks"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	repomocks "github.com/NeuralTrust/TrustGate/pkg/domain/consumer/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	policydomain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	policymocks "github.com/NeuralTrust/TrustGate/pkg/domain/policy/mocks"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	backendmocks "github.com/NeuralTrust/TrustGate/pkg/domain/registry/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	cachemocks "github.com/NeuralTrust/TrustGate/pkg/infra/cache/mocks"
	"github.com/stretchr/testify/mock"
)

func newAssociator(
	repo *repomocks.Repository,
	registryRepo *backendmocks.Repository,
	authRepo *authmocks.Repository,
	policyRepo *policymocks.Repository,
	publisher *cachemocks.EventPublisher,
	resolver ...*fakeProtocolResolver,
) appconsumer.Associator {
	return newAssociatorWithGuard(repo, registryRepo, authRepo, policyRepo, publisher, &stubLevelGuard{}, resolver...)
}

// newAssociatorWithGuard is newAssociator with a level guard the test drives,
// which is how the attach path is observed without a database.
func newAssociatorWithGuard(
	repo *repomocks.Repository,
	registryRepo *backendmocks.Repository,
	authRepo *authmocks.Repository,
	policyRepo *policymocks.Repository,
	publisher *cachemocks.EventPublisher,
	levels apppolicy.LevelGuard,
	resolver ...*fakeProtocolResolver,
) appconsumer.Associator {
	res := &fakeProtocolResolver{}
	if len(resolver) > 0 {
		res = resolver[0]
	}
	return appconsumer.NewAssociator(
		repo, registryRepo, authRepo, policyRepo, levels,
		newCacheManager(), publisher, newTestLogger(), nil, res,
	)
}

// stubLevelGuard answers with err, and lets the write through when there is
// none, recording the policy it was asked about.
type stubLevelGuard struct {
	err     error
	checked *policydomain.Policy
}

func (g *stubLevelGuard) Check(ctx context.Context, p *policydomain.Policy, write func(context.Context) error) error {
	g.checked = p
	if g.err != nil {
		return g.err
	}
	return write(ctx)
}

type fakeProtocolResolver struct {
	protocols     map[string][]string
	settingsError error
	inertSafe     map[string]bool
}

func (f *fakeProtocolResolver) SupportedProtocols(slug string) ([]string, bool) {
	p, ok := f.protocols[slug]
	return p, ok
}

func (f *fakeProtocolResolver) ValidateSettingsForProtocol(string, string, map[string]any) error {
	return f.settingsError
}

func (f *fakeProtocolResolver) InertSafe(slug string) bool {
	return f.inertSafe[slug]
}

func TestAssociator_AttachRegistry_Success(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	consumerID := ids.New[ids.ConsumerKind]()
	registryID := ids.New[ids.RegistryKind]()

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, consumerID).
		Return(&domain.Consumer{ID: consumerID, GatewayID: gwID}, nil).Once()
	repo.EXPECT().AttachRegistry(mock.Anything, consumerID, registryID, intPtr(1)).Return(nil).Once()

	registryRepo := backendmocks.NewRepository(t)
	registryRepo.EXPECT().FindByID(mock.Anything, registryID).
		Return(&registrydomain.Registry{ID: registryID, GatewayID: gwID}, nil).Once()

	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: gwID.String()}).
		Return(nil).
		Once()

	a := newAssociator(repo, registryRepo, authmocks.NewRepository(t), policymocks.NewRepository(t), publisher)
	if err := a.AttachRegistry(context.Background(), gwID, consumerID, registryID, intPtr(1)); err != nil {
		t.Fatalf("AttachRegistry error: %v", err)
	}
}

func intPtr(i int) *int { return &i }

// A server whose address is completed from per-user values has nowhere to read
// them for an application that acts as itself: it never installs from the Store,
// so it holds no config and no vault entries, and there is no admin-level place
// to supply them. The binding used to be accepted and every call then died at
// dial time on a missing placeholder.
// Binding a server whose URL is completed per user is no longer refused here.
//
// It used to be, on a consumer that declared it had no users: the values live
// on a caller's own Store installation and the call would die at dial time with
// a placeholder nobody could fill. Nothing declares that any more — the same
// application serves a person on one request and nobody on the next — so the
// only place that can still tell the truth is the dial, per caller.
func TestAssociator_AttachRegistry_AllowsPerUserURL(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	consumerID := ids.New[ids.ConsumerKind]()
	registryID := ids.New[ids.RegistryKind]()

	perUser := &registrydomain.Registry{
		ID: registryID, GatewayID: gwID, Type: registrydomain.TypeMCP,
		MCPTarget: &registrydomain.MCPTarget{
			URL: "https://{account_url}/mcp",
			URLVariables: []registrydomain.MCPURLVariable{
				{Name: "account_url", Required: true},
			},
		},
	}

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, consumerID).
		Return(&domain.Consumer{ID: consumerID, GatewayID: gwID, Type: domain.TypeMCP}, nil).Once()
	repo.EXPECT().AttachRegistry(mock.Anything, consumerID, registryID, mock.Anything).Return(nil).Once()
	registryRepo := backendmocks.NewRepository(t)
	registryRepo.EXPECT().FindByID(mock.Anything, registryID).Return(perUser, nil).Once()
	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().Publish(mock.Anything, mock.Anything).Return(nil).Maybe()

	a := newAssociator(repo, registryRepo, authmocks.NewRepository(t), policymocks.NewRepository(t), publisher)
	if err := a.AttachRegistry(context.Background(), gwID, consumerID, registryID, intPtr(1)); err != nil {
		t.Fatalf("AttachRegistry: %v", err)
	}
}

// The same server on a consumer that acts for users is fine: each caller brings
// their own values.
func TestAssociator_AttachRegistry_AllowsPerUserURLWhenActingForUsers(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	consumerID := ids.New[ids.ConsumerKind]()
	registryID := ids.New[ids.RegistryKind]()

	perUser := &registrydomain.Registry{
		ID: registryID, GatewayID: gwID, Type: registrydomain.TypeMCP,
		MCPTarget: &registrydomain.MCPTarget{
			URL: "https://{account_url}/mcp",
			URLVariables: []registrydomain.MCPURLVariable{
				{Name: "account_url", Required: true},
			},
		},
	}

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, consumerID).Return(&domain.Consumer{
		ID: consumerID, GatewayID: gwID, Type: domain.TypeMCP,
		Identity: domain.Identity{},
	}, nil).Once()
	repo.EXPECT().AttachRegistry(mock.Anything, consumerID, registryID, intPtr(1)).Return(nil).Once()
	registryRepo := backendmocks.NewRepository(t)
	registryRepo.EXPECT().FindByID(mock.Anything, registryID).Return(perUser, nil).Once()

	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: gwID.String()}).
		Return(nil).Once()

	a := newAssociator(repo, registryRepo, authmocks.NewRepository(t), policymocks.NewRepository(t), publisher)
	if err := a.AttachRegistry(context.Background(), gwID, consumerID, registryID, intPtr(1)); err != nil {
		t.Fatalf("AttachRegistry error: %v", err)
	}
}

func TestAssociator_AttachRegistry_RejectsForeignConsumer(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	consumerID := ids.New[ids.ConsumerKind]()
	registryID := ids.New[ids.RegistryKind]()

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, consumerID).
		Return(&domain.Consumer{ID: consumerID, GatewayID: ids.New[ids.GatewayKind]()}, nil).Once()

	publisher := cachemocks.NewEventPublisher(t)
	a := newAssociator(repo, backendmocks.NewRepository(t), authmocks.NewRepository(t), policymocks.NewRepository(t), publisher)
	err := a.AttachRegistry(context.Background(), gwID, consumerID, registryID, intPtr(1))
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want consumer ErrNotFound", err)
	}
	publisher.AssertNotCalled(t, "Publish", mock.Anything, mock.Anything)
}

func TestAssociator_AttachRegistry_RejectsForeignRegistry(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	consumerID := ids.New[ids.ConsumerKind]()
	registryID := ids.New[ids.RegistryKind]()

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, consumerID).
		Return(&domain.Consumer{ID: consumerID, GatewayID: gwID}, nil).Once()

	registryRepo := backendmocks.NewRepository(t)
	registryRepo.EXPECT().FindByID(mock.Anything, registryID).
		Return(&registrydomain.Registry{ID: registryID, GatewayID: ids.New[ids.GatewayKind]()}, nil).Once()

	publisher := cachemocks.NewEventPublisher(t)
	a := newAssociator(repo, registryRepo, authmocks.NewRepository(t), policymocks.NewRepository(t), publisher)
	err := a.AttachRegistry(context.Background(), gwID, consumerID, registryID, intPtr(1))
	if !errors.Is(err, registrydomain.ErrNotFound) {
		t.Fatalf("err = %v, want registry ErrNotFound", err)
	}
	publisher.AssertNotCalled(t, "Publish", mock.Anything, mock.Anything)
}

func TestAssociator_DetachRegistry_RejectsDependentReferences(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	consumerID := ids.New[ids.ConsumerKind]()
	registryID := ids.New[ids.RegistryKind]()

	repo := repomocks.NewRepository(t)
	repo.EXPECT().
		DetachRegistryIfUnreferenced(mock.Anything, gwID, consumerID, registryID).
		Return(nil, commonerrors.ErrConflict).
		Once()

	publisher := cachemocks.NewEventPublisher(t)
	a := newAssociator(repo, backendmocks.NewRepository(t), authmocks.NewRepository(t), policymocks.NewRepository(t), publisher)
	err := a.DetachRegistry(context.Background(), gwID, consumerID, registryID)
	if !errors.Is(err, commonerrors.ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict", err)
	}
	publisher.AssertNotCalled(t, "Publish", mock.Anything, mock.Anything)
}

func TestAssociator_AttachPolicy_Success(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	consumerID := ids.New[ids.ConsumerKind]()
	policyID := ids.New[ids.PolicyKind]()

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, consumerID).
		Return(&domain.Consumer{ID: consumerID, GatewayID: gwID, Type: domain.TypeLLM}, nil).Once()
	repo.EXPECT().AttachPolicy(mock.Anything, consumerID, policyID).Return(nil).Once()

	policyRepo := policymocks.NewRepository(t)
	policyRepo.EXPECT().FindByID(mock.Anything, policyID).
		Return(&policydomain.Policy{ID: policyID, GatewayID: gwID, Slug: "cors"}, nil).Once()

	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: gwID.String()}).
		Return(nil).
		Once()

	resolver := &fakeProtocolResolver{protocols: map[string][]string{"cors": {"LLM", "MCP"}}}
	a := newAssociator(repo, backendmocks.NewRepository(t), authmocks.NewRepository(t), policyRepo, publisher, resolver)
	if err := a.AttachPolicy(context.Background(), gwID, consumerID, policyID); err != nil {
		t.Fatalf("AttachPolicy error: %v", err)
	}
}

func TestAssociator_AttachPolicy_ProtocolValidation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name              string
		consumerType      domain.Type
		global            bool
		slug              string
		resolverProtocols map[string][]string
		wantAttach        bool
		wantMismatch      bool
	}{
		{
			name:              "reject llm-only policy for mcp consumer",
			consumerType:      domain.TypeMCP,
			slug:              "cost_cap",
			resolverProtocols: map[string][]string{"cost_cap": {"LLM"}},
			wantMismatch:      true,
		},
		{
			name:              "reject mcp-only policy for llm consumer",
			consumerType:      domain.TypeLLM,
			slug:              "per_tool_rate_limiter",
			resolverProtocols: map[string][]string{"per_tool_rate_limiter": {"MCP"}},
			wantMismatch:      true,
		},
		{
			name:              "allow dual-protocol policy for llm consumer",
			consumerType:      domain.TypeLLM,
			slug:              "trustguard",
			resolverProtocols: map[string][]string{"trustguard": {"LLM", "MCP"}},
			wantAttach:        true,
		},
		{
			name:              "allow dual-protocol policy for mcp consumer",
			consumerType:      domain.TypeMCP,
			slug:              "cors",
			resolverProtocols: map[string][]string{"cors": {"LLM", "MCP"}},
			wantAttach:        true,
		},
		{
			name:              "allow matching single-protocol policy",
			consumerType:      domain.TypeLLM,
			slug:              "cost_cap",
			resolverProtocols: map[string][]string{"cost_cap": {"LLM"}},
			wantAttach:        true,
		},
		{
			name:              "skip validation for global policy",
			consumerType:      domain.TypeMCP,
			global:            true,
			slug:              "cost_cap",
			resolverProtocols: map[string][]string{"cost_cap": {"LLM"}},
			wantAttach:        true,
		},
		{
			name:              "skip validation for a2a consumer",
			consumerType:      domain.TypeA2A,
			slug:              "cost_cap",
			resolverProtocols: map[string][]string{"cost_cap": {"LLM"}},
			wantAttach:        true,
		},
		{
			name:              "skip validation for unknown slug",
			consumerType:      domain.TypeMCP,
			slug:              "unknown",
			resolverProtocols: map[string][]string{},
			wantAttach:        true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gwID := ids.New[ids.GatewayKind]()
			consumerID := ids.New[ids.ConsumerKind]()
			policyID := ids.New[ids.PolicyKind]()

			repo := repomocks.NewRepository(t)
			repo.EXPECT().FindByID(mock.Anything, consumerID).
				Return(&domain.Consumer{ID: consumerID, GatewayID: gwID, Type: tt.consumerType}, nil).Once()
			if tt.wantAttach {
				repo.EXPECT().AttachPolicy(mock.Anything, consumerID, policyID).Return(nil).Once()
			}

			policyRepo := policymocks.NewRepository(t)
			policyRepo.EXPECT().FindByID(mock.Anything, policyID).
				Return(&policydomain.Policy{ID: policyID, GatewayID: gwID, Slug: tt.slug, Global: tt.global}, nil).Once()

			publisher := cachemocks.NewEventPublisher(t)
			if tt.wantAttach {
				publisher.EXPECT().
					Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: gwID.String()}).
					Return(nil).
					Once()
			}

			resolver := &fakeProtocolResolver{protocols: tt.resolverProtocols}
			a := newAssociator(repo, backendmocks.NewRepository(t), authmocks.NewRepository(t), policyRepo, publisher, resolver)

			err := a.AttachPolicy(context.Background(), gwID, consumerID, policyID)
			if tt.wantMismatch {
				if !errors.Is(err, domain.ErrPolicyProtocolMismatch) {
					t.Fatalf("err = %v, want ErrPolicyProtocolMismatch", err)
				}
				publisher.AssertNotCalled(t, "Publish", mock.Anything, mock.Anything)
				return
			}
			if err != nil {
				t.Fatalf("AttachPolicy error: %v", err)
			}
		})
	}
}

// A plugin may support a protocol and still carry a setting that protocol
// cannot honour, so supporting it is not the end of the check.
func TestAssociator_AttachPolicy_SettingsUnsupportedOnConsumerProtocol(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	consumerID := ids.New[ids.ConsumerKind]()
	policyID := ids.New[ids.PolicyKind]()

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, consumerID).
		Return(&domain.Consumer{ID: consumerID, GatewayID: gwID, Type: domain.TypeMCP}, nil).Once()

	policyRepo := policymocks.NewRepository(t)
	policyRepo.EXPECT().FindByID(mock.Anything, policyID).
		Return(&policydomain.Policy{ID: policyID, GatewayID: gwID, Slug: "cost_cap"}, nil).Once()

	publisher := cachemocks.NewEventPublisher(t)
	resolver := &fakeProtocolResolver{
		protocols:     map[string][]string{"cost_cap": {"LLM", "MCP"}},
		settingsError: errors.New("behavior cannot be honoured on MCP"),
	}
	a := newAssociator(repo, backendmocks.NewRepository(t), authmocks.NewRepository(t), policyRepo, publisher, resolver)

	err := a.AttachPolicy(context.Background(), gwID, consumerID, policyID)

	if !errors.Is(err, domain.ErrPolicyProtocolMismatch) {
		t.Fatalf("err = %v, want ErrPolicyProtocolMismatch", err)
	}
	if !strings.Contains(err.Error(), "behavior cannot be honoured on MCP") {
		t.Fatalf("err = %v, want the plugin's own complaint to reach the operator", err)
	}
	publisher.AssertNotCalled(t, "Publish", mock.Anything, mock.Anything)
}

func TestAssociator_AttachAuth_Success(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	consumerID := ids.New[ids.ConsumerKind]()
	authID := ids.New[ids.AuthKind]()

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, consumerID).
		Return(&domain.Consumer{ID: consumerID, GatewayID: gwID}, nil).Once()
	repo.EXPECT().AttachAuth(mock.Anything, consumerID, authID).Return(nil).Once()

	authRepo := authmocks.NewRepository(t)
	authRepo.EXPECT().FindByID(mock.Anything, authID).
		Return(&authdomain.Auth{ID: authID, GatewayID: gwID}, nil).Once()

	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: gwID.String()}).
		Return(nil).
		Once()

	a := newAssociator(repo, backendmocks.NewRepository(t), authRepo, policymocks.NewRepository(t), publisher)
	if err := a.AttachAuth(context.Background(), gwID, consumerID, authID); err != nil {
		t.Fatalf("AttachAuth error: %v", err)
	}
}

// Attaching a provider stored under the deprecated alias to an MCP consumer is
// accepted: the alias is oauth2. Capability gates what the gateway advertises
// as an authorization server, not whether a credential may be attached.
func TestAssociator_AttachAuth_MCPAcceptsAliasedIdP(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	consumerID := ids.New[ids.ConsumerKind]()
	authID := ids.New[ids.AuthKind]()

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, consumerID).
		Return(&domain.Consumer{ID: consumerID, GatewayID: gwID, Type: domain.TypeMCP}, nil).Once()

	authRepo := authmocks.NewRepository(t)
	authRepo.EXPECT().FindByID(mock.Anything, authID).
		Return(&authdomain.Auth{ID: authID, GatewayID: gwID, Type: authdomain.TypeOIDC}, nil).Once()

	repo.EXPECT().AttachAuth(mock.Anything, consumerID, authID).Return(nil).Once()
	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().Publish(mock.Anything, mock.Anything).Return(nil).Once()
	a := newAssociator(repo, backendmocks.NewRepository(t), authRepo, policymocks.NewRepository(t), publisher)
	if err := a.AttachAuth(context.Background(), gwID, consumerID, authID); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAssociator_AttachAuth_MCPAcceptsOAuth2(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	consumerID := ids.New[ids.ConsumerKind]()
	authID := ids.New[ids.AuthKind]()

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, consumerID).
		Return(&domain.Consumer{ID: consumerID, GatewayID: gwID, Type: domain.TypeMCP}, nil).Once()
	repo.EXPECT().AttachAuth(mock.Anything, consumerID, authID).Return(nil).Once()

	authRepo := authmocks.NewRepository(t)
	authRepo.EXPECT().FindByID(mock.Anything, authID).
		Return(&authdomain.Auth{ID: authID, GatewayID: gwID, Type: authdomain.TypeOAuth2}, nil).Once()

	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: gwID.String()}).
		Return(nil).
		Once()

	a := newAssociator(repo, backendmocks.NewRepository(t), authRepo, policymocks.NewRepository(t), publisher)
	if err := a.AttachAuth(context.Background(), gwID, consumerID, authID); err != nil {
		t.Fatalf("AttachAuth error: %v", err)
	}
}

func TestAssociator_DetachPolicy_Success(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	consumerID := ids.New[ids.ConsumerKind]()
	policyID := ids.New[ids.PolicyKind]()

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, consumerID).
		Return(&domain.Consumer{ID: consumerID, GatewayID: gwID}, nil).Once()
	repo.EXPECT().DetachPolicy(mock.Anything, consumerID, policyID).Return(nil).Once()

	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: gwID.String()}).
		Return(nil).
		Once()

	a := newAssociator(repo, backendmocks.NewRepository(t), authmocks.NewRepository(t), policymocks.NewRepository(t), publisher)
	if err := a.DetachPolicy(context.Background(), gwID, consumerID, policyID); err != nil {
		t.Fatalf("DetachPolicy error: %v", err)
	}
}

// The guard is about the scope's dimension and the plugin behind the policy,
// not about the consumer's type: outside MCP a registry or a tool has no
// meaning, and a plugin that resolves tool names would read an inert group as
// "everyone". A group-only scope over a plugin that does not read names is the
// one combination that crosses (RUN-1621, rules 2 and 7).
func TestAssociator_AttachPolicy_ScopeMustCrossIntoTheConsumerPlane(t *testing.T) {
	t.Parallel()
	inertSafeSlug := "inert_safe_guard"
	nameGatingSlug := "trustguard"
	tests := []struct {
		name         string
		consumerType domain.Type
		slug         string
		scope        *policydomain.MCPScope
		wantAttach   bool
		wantReason   string
	}{
		{
			name:         "reject registry scope on llm consumer even when the plugin is inert-safe",
			consumerType: domain.TypeLLM,
			slug:         inertSafeSlug,
			scope:        &policydomain.MCPScope{RegistryIDs: []ids.RegistryID{ids.New[ids.RegistryKind]()}},
			wantReason:   "names a registry or a tool",
		},
		{
			name:         "reject tool scope on a2a consumer",
			consumerType: domain.TypeA2A,
			slug:         inertSafeSlug,
			scope: &policydomain.MCPScope{Tools: []policydomain.MCPToolRef{
				{RegistryID: ids.New[ids.RegistryKind](), Tool: "run_query"},
			}},
			wantReason: "names a registry or a tool",
		},
		{
			name:         "reject pruned scope on llm consumer",
			consumerType: domain.TypeLLM,
			slug:         inertSafeSlug,
			scope:        &policydomain.MCPScope{},
			wantReason:   "empty and names nothing",
		},
		{
			name:         "reject group-only scope when the plugin gates by name",
			consumerType: domain.TypeLLM,
			slug:         nameGatingSlug,
			scope:        &policydomain.MCPScope{ExceptGroups: []string{"Finanzas"}},
			wantReason:   "has not opted into running where the scope is inert",
		},
		{
			name:         "allow group-only scope when the plugin is inert-safe",
			consumerType: domain.TypeLLM,
			slug:         inertSafeSlug,
			scope:        &policydomain.MCPScope{Groups: []string{"Finanzas"}},
			wantAttach:   true,
		},
		{
			name:         "allow a name-gating plugin with any scope on an mcp consumer",
			consumerType: domain.TypeMCP,
			slug:         nameGatingSlug,
			scope:        &policydomain.MCPScope{Groups: []string{"Finanzas"}},
			wantAttach:   true,
		},
		{
			name:         "allow unscoped policy on llm consumer",
			consumerType: domain.TypeLLM,
			slug:         nameGatingSlug,
			wantAttach:   true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gwID := ids.New[ids.GatewayKind]()
			consumerID := ids.New[ids.ConsumerKind]()
			policyID := ids.New[ids.PolicyKind]()

			repo := repomocks.NewRepository(t)
			repo.EXPECT().FindByID(mock.Anything, consumerID).
				Return(&domain.Consumer{ID: consumerID, GatewayID: gwID, Type: tt.consumerType}, nil).Once()
			policyRepo := policymocks.NewRepository(t)
			policyRepo.EXPECT().FindByID(mock.Anything, policyID).
				Return(&policydomain.Policy{ID: policyID, GatewayID: gwID, Slug: tt.slug, MCPScope: tt.scope}, nil).Once()
			publisher := cachemocks.NewEventPublisher(t)
			if tt.wantAttach {
				repo.EXPECT().AttachPolicy(mock.Anything, consumerID, policyID).Return(nil).Once()
				publisher.EXPECT().
					Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: gwID.String()}).
					Return(nil).
					Once()
			}
			resolver := &fakeProtocolResolver{
				protocols: map[string][]string{
					nameGatingSlug: {"LLM", "MCP"},
					inertSafeSlug:  {"LLM", "MCP"},
				},
				inertSafe: map[string]bool{inertSafeSlug: true},
			}
			a := newAssociator(repo, backendmocks.NewRepository(t), authmocks.NewRepository(t), policyRepo, publisher, resolver)

			err := a.AttachPolicy(context.Background(), gwID, consumerID, policyID)
			if tt.wantAttach {
				if err != nil {
					t.Fatalf("AttachPolicy error: %v", err)
				}
				return
			}
			if !errors.Is(err, domain.ErrPolicyScopeDoesNotCross) {
				t.Fatalf("err = %v, want ErrPolicyScopeDoesNotCross", err)
			}
			if !errors.Is(err, domain.ErrPolicyProtocolMismatch) || !errors.Is(err, commonerrors.ErrValidation) {
				t.Fatalf("err = %v, want it to read as a protocol mismatch and a validation error", err)
			}
			if !strings.Contains(err.Error(), tt.wantReason) {
				t.Fatalf("err = %v, want it to give the reason %q", err, tt.wantReason)
			}
			if !strings.Contains(err.Error(), string(tt.consumerType)) {
				t.Fatalf("err = %v, want it to name the consumer type", err)
			}
			repo.AssertNotCalled(t, "AttachPolicy", mock.Anything, mock.Anything, mock.Anything)
			publisher.AssertNotCalled(t, "Publish", mock.Anything, mock.Anything)
		})
	}
}

// Attaching a consumer takes the levels that consumer adds, so it goes through
// the level guard and the junction row is never written when it is refused.
func TestAssociator_AttachPolicy_RefusesAnOccupiedLevel(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	consumerID := ids.New[ids.ConsumerKind]()
	policyID := ids.New[ids.PolicyKind]()

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, consumerID).
		Return(&domain.Consumer{ID: consumerID, GatewayID: gwID, Type: domain.TypeLLM}, nil).Once()

	policyRepo := policymocks.NewRepository(t)
	policyRepo.EXPECT().FindByID(mock.Anything, policyID).
		Return(&policydomain.Policy{ID: policyID, GatewayID: gwID, Slug: "cors", Enabled: true}, nil).Once()

	levels := &stubLevelGuard{err: policydomain.ErrPolicyLevelConflict}
	a := newAssociatorWithGuard(repo, backendmocks.NewRepository(t), authmocks.NewRepository(t), policyRepo,
		cachemocks.NewEventPublisher(t), levels)

	err := a.AttachPolicy(context.Background(), gwID, consumerID, policyID)
	if !errors.Is(err, policydomain.ErrPolicyLevelConflict) {
		t.Fatalf("err = %v, want ErrPolicyLevelConflict", err)
	}
	repo.AssertNotCalled(t, "AttachPolicy", mock.Anything, mock.Anything, mock.Anything)
	if len(levels.checked.ConsumerIDs) != 1 || levels.checked.ConsumerIDs[0] != consumerID {
		t.Fatalf("guard saw consumers %v, want only %s", levels.checked.ConsumerIDs, consumerID)
	}
}

// Detaching a consumer only releases levels, so it never asks the guard.
func TestAssociator_DetachPolicy_IsNotGuarded(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	consumerID := ids.New[ids.ConsumerKind]()
	policyID := ids.New[ids.PolicyKind]()

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, consumerID).
		Return(&domain.Consumer{ID: consumerID, GatewayID: gwID, Type: domain.TypeLLM}, nil).Once()
	repo.EXPECT().DetachPolicy(mock.Anything, consumerID, policyID).Return(nil).Once()

	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: gwID.String()}).
		Return(nil).
		Once()

	levels := &stubLevelGuard{err: policydomain.ErrPolicyLevelConflict}
	a := newAssociatorWithGuard(repo, backendmocks.NewRepository(t), authmocks.NewRepository(t),
		policymocks.NewRepository(t), publisher, levels)

	if err := a.DetachPolicy(context.Background(), gwID, consumerID, policyID); err != nil {
		t.Fatalf("DetachPolicy error: %v", err)
	}
	if levels.checked != nil {
		t.Fatal("detach must not consult the level guard")
	}
}

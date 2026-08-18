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

package mcp

import (
	"context"
	"fmt"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// SubscriptionTargetResolver resolves fresh role-scoped, credentialed subscription targets.
type SubscriptionTargetResolver interface {
	Resolve(
		ctx context.Context,
		gatewayID ids.GatewayID,
		path string,
		requested HonouredSet,
	) ([]SubscriptionRequest, error)
}

// SubscriptionTargetRefresher freshly resolves one previously bound registry target.
type SubscriptionTargetRefresher interface {
	Refresh(ctx context.Context, request SubscriptionRequest) (SubscriptionRequest, error)
}

type subscriptionTargetResolver struct {
	finder appconsumer.DataFinder
	scoper RoleScoper
	creds  CredentialResolver
}

// NewSubscriptionTargetResolver builds the application target-resolution service.
func NewSubscriptionTargetResolver(
	finder appconsumer.DataFinder,
	scoper RoleScoper,
	creds CredentialResolver,
) SubscriptionTargetResolver {
	return &subscriptionTargetResolver{finder: finder, scoper: scoper, creds: creds}
}

func (r *subscriptionTargetResolver) Resolve(
	ctx context.Context,
	gatewayID ids.GatewayID,
	path string,
	requested HonouredSet,
) ([]SubscriptionRequest, error) {
	data, err := r.finder.FindByGateway(ctx, gatewayID)
	if err != nil {
		return nil, fmt.Errorf("mcp: resolve subscription consumer data: %w", err)
	}
	rc, ok := data.MatchPath(path)
	if !ok || rc == nil || rc.Consumer == nil || rc.Consumer.Type != consumerdomain.TypeMCP {
		return nil, fmt.Errorf("%w: subscription consumer is unavailable", ErrSubscriptionRevoked)
	}
	scoped, err := r.scoper.Scope(ctx, rc, data)
	if err != nil {
		return nil, fmt.Errorf("mcp: resolve subscription role scope: %w", err)
	}
	if scoped == nil || scoped.Consumer == nil ||
		scoped.Consumer.ProtocolAcceptance() == consumerdomain.ProtocolAcceptanceLegacyOnly {
		return nil, nil
	}
	authID, hasAuthID := appconsumer.AuthIDFromContext(ctx)
	authIDValue := ""
	if hasAuthID {
		authIDValue = authID.String()
	}
	baseIdentity := SubscriptionIdentity{
		GatewayID:            gatewayID.String(),
		ConsumerID:           scoped.Consumer.ID.String(),
		PrincipalFingerprint: principalFingerprint(ctx),
		AuthID:               authIDValue,
		RoleScopeFingerprint: SurfaceConfigFingerprint(scoped),
		Path:                 path,
	}
	requests := make([]SubscriptionRequest, 0, len(scoped.Registries))
	for _, reg := range scoped.Registries {
		if !eligibleSubscriptionRegistry(reg) {
			continue
		}
		kinds := registryRequestedKinds(scoped, reg, requested)
		if kinds.Empty() {
			continue
		}
		target := targetFor(ctx, scoped, reg)
		if r.creds != nil {
			if err := r.creds.Apply(ctx, scoped, reg, &target); err != nil {
				return nil, fmt.Errorf("mcp: resolve subscription credentials: %w", err)
			}
		}
		identity := baseIdentity
		identity.RegistryID = reg.ID.String()
		requests = append(requests, SubscriptionRequest{
			Identity:  identity,
			Target:    target,
			Requested: kinds,
		})
	}
	return requests, nil
}

func (r *subscriptionTargetResolver) Refresh(
	ctx context.Context,
	request SubscriptionRequest,
) (SubscriptionRequest, error) {
	gatewayID, err := ids.Parse[ids.GatewayKind](request.Identity.GatewayID)
	if err != nil {
		return SubscriptionRequest{}, fmt.Errorf("%w: invalid gateway binding", ErrSubscriptionRevoked)
	}
	requests, err := r.Resolve(ctx, gatewayID, request.Identity.Path, request.Requested)
	if err != nil {
		return SubscriptionRequest{}, err
	}
	for _, current := range requests {
		if current.Identity.RegistryID == request.Identity.RegistryID {
			return current, nil
		}
	}
	return SubscriptionRequest{}, fmt.Errorf("%w: registry binding changed", ErrSubscriptionRevoked)
}

func eligibleSubscriptionRegistry(reg *registrydomain.Registry) bool {
	if reg == nil || !reg.Enabled || !reg.IsMCP() || reg.MCPTarget == nil {
		return false
	}
	return reg.MCPTarget.ProtocolMode != registrydomain.MCPProtocolModeLegacy
}

func registryRequestedKinds(
	rc *appconsumer.RoutableConsumer,
	reg *registrydomain.Registry,
	requested HonouredSet,
) HonouredSet {
	toolkit := rc.Consumer.Toolkit()
	if toolkit == nil {
		return requested
	}
	visible := make([]NotificationKind, 0, 3)
	if len(toolkit.EntriesFor(reg.ID)) > 0 && requested.Has(NotificationToolsListChanged) {
		visible = append(visible, NotificationToolsListChanged)
	}
	if len(toolkit.PromptEntriesFor(reg.ID)) > 0 && requested.Has(NotificationPromptsListChanged) {
		visible = append(visible, NotificationPromptsListChanged)
	}
	if len(toolkit.ResourceEntriesFor(reg.ID)) > 0 && requested.Has(NotificationResourcesListChanged) {
		visible = append(visible, NotificationResourcesListChanged)
	}
	return NewHonouredSet(visible...)
}

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

package consumer

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	policydomain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	roledomain "github.com/NeuralTrust/TrustGate/pkg/domain/role"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
)

//go:generate mockery --name=Associator --dir=. --output=./mocks --filename=consumer_associator_mock.go --case=underscore --with-expecter
type Associator interface {
	AttachRegistry(ctx context.Context, gatewayID ids.GatewayID, consumerID ids.ConsumerID, registryID ids.RegistryID, weight *int) error
	DetachRegistry(ctx context.Context, gatewayID ids.GatewayID, consumerID ids.ConsumerID, registryID ids.RegistryID) error
	AttachRole(ctx context.Context, gatewayID ids.GatewayID, consumerID ids.ConsumerID, roleID ids.RoleID) error
	DetachRole(ctx context.Context, gatewayID ids.GatewayID, consumerID ids.ConsumerID, roleID ids.RoleID) error
	AttachAuth(ctx context.Context, gatewayID ids.GatewayID, consumerID ids.ConsumerID, authID ids.AuthID) error
	DetachAuth(ctx context.Context, gatewayID ids.GatewayID, consumerID ids.ConsumerID, authID ids.AuthID) error
	AttachPolicy(ctx context.Context, gatewayID ids.GatewayID, consumerID ids.ConsumerID, policyID ids.PolicyID) error
	DetachPolicy(ctx context.Context, gatewayID ids.GatewayID, consumerID ids.ConsumerID, policyID ids.PolicyID) error
}

var _ Associator = (*associator)(nil)

type associator struct {
	repo         domain.Repository
	registryRepo registrydomain.Repository
	roleRepo     roledomain.Repository
	authRepo     authdomain.Repository
	policyRepo   policydomain.Repository
	memoryCache  *cache.TTLMap
	policyCache  *cache.TTLMap
	publisher    cache.EventPublisher
	logger       *slog.Logger
	signaler     configsyncport.SnapshotSignaler
	resolver     pluginProtocolResolver
}

func NewAssociator(
	repo domain.Repository,
	registryRepo registrydomain.Repository,
	roleRepo roledomain.Repository,
	authRepo authdomain.Repository,
	policyRepo policydomain.Repository,
	manager *cache.TTLMapManager,
	publisher cache.EventPublisher,
	logger *slog.Logger,
	signaler configsyncport.SnapshotSignaler,
	resolver pluginProtocolResolver,
) Associator {
	return &associator{
		repo:         repo,
		registryRepo: registryRepo,
		roleRepo:     roleRepo,
		authRepo:     authRepo,
		policyRepo:   policyRepo,
		memoryCache:  manager.GetTTLMap(cache.ConsumerTTLName),
		policyCache:  manager.GetTTLMap(cache.PolicyTTLName),
		publisher:    publisher,
		logger:       logger,
		signaler:     signaler,
		resolver:     resolver,
	}
}

func (a *associator) AttachRegistry(ctx context.Context, gatewayID ids.GatewayID, consumerID ids.ConsumerID, registryID ids.RegistryID, weight *int) error {
	cons, err := a.consumerInGateway(ctx, gatewayID, consumerID)
	if err != nil {
		return err
	}
	if cons.RoutingMode == domain.RoutingModeRoleBased {
		return commonerrors.ErrConflict
	}
	reg, err := a.registryInGateway(ctx, gatewayID, registryID)
	if err != nil {
		return err
	}
	if string(reg.Type) != string(cons.Type) {
		return fmt.Errorf("%w: registry of type %s cannot be attached to a consumer of type %s",
			registrydomain.ErrInvalidRegistryID, reg.Type, cons.Type)
	}
	if err := a.repo.AttachRegistry(ctx, consumerID, registryID, weight); err != nil {
		return err
	}
	a.invalidate(ctx, cons)
	return nil
}

func (a *associator) DetachRegistry(ctx context.Context, gatewayID ids.GatewayID, consumerID ids.ConsumerID, registryID ids.RegistryID) error {
	cons, err := a.repo.DetachRegistryIfUnreferenced(ctx, gatewayID, consumerID, registryID)
	if err != nil {
		return err
	}
	a.invalidate(ctx, cons)
	return nil
}

func (a *associator) AttachRole(ctx context.Context, gatewayID ids.GatewayID, consumerID ids.ConsumerID, roleID ids.RoleID) error {
	cons, err := a.consumerInGateway(ctx, gatewayID, consumerID)
	if err != nil {
		return err
	}
	if cons.RoutingMode == domain.RoutingModeInline {
		return commonerrors.ErrConflict
	}
	if err := a.roleInGateway(ctx, gatewayID, roleID); err != nil {
		return err
	}
	if err := a.repo.AttachRole(ctx, consumerID, roleID); err != nil {
		return err
	}
	a.invalidate(ctx, cons)
	return nil
}

func (a *associator) DetachRole(ctx context.Context, gatewayID ids.GatewayID, consumerID ids.ConsumerID, roleID ids.RoleID) error {
	cons, err := a.consumerInGateway(ctx, gatewayID, consumerID)
	if err != nil {
		return err
	}
	if err := a.repo.DetachRole(ctx, consumerID, roleID); err != nil {
		return err
	}
	a.invalidate(ctx, cons)
	return nil
}

func (a *associator) AttachAuth(ctx context.Context, gatewayID ids.GatewayID, consumerID ids.ConsumerID, authID ids.AuthID) error {
	cons, err := a.consumerInGateway(ctx, gatewayID, consumerID)
	if err != nil {
		return err
	}
	au, err := a.authInGateway(ctx, gatewayID, authID)
	if err != nil {
		return err
	}
	if err := domain.ValidateAuthType(cons.Type, cons.RoutingMode, au.Type); err != nil {
		return err
	}
	if cons.RoutingMode == domain.RoutingModeRoleBased {
		if err := validateRoleBasedAuthCount(cons, au.ID); err != nil {
			return err
		}
	}
	if err := a.repo.AttachAuth(ctx, consumerID, authID); err != nil {
		return err
	}
	a.invalidate(ctx, cons)
	return nil
}

func validateRoleBasedAuthCount(cons *domain.Consumer, authID ids.AuthID) error {
	for _, existing := range cons.AuthIDs {
		if existing != authID {
			return fmt.Errorf(
				"%w: a role_based consumer can have at most one auth",
				commonerrors.ErrConflict,
			)
		}
	}
	return nil
}

func (a *associator) DetachAuth(ctx context.Context, gatewayID ids.GatewayID, consumerID ids.ConsumerID, authID ids.AuthID) error {
	cons, err := a.consumerInGateway(ctx, gatewayID, consumerID)
	if err != nil {
		return err
	}
	if err := a.repo.DetachAuth(ctx, consumerID, authID); err != nil {
		return err
	}
	a.invalidate(ctx, cons)
	return nil
}

func (a *associator) AttachPolicy(ctx context.Context, gatewayID ids.GatewayID, consumerID ids.ConsumerID, policyID ids.PolicyID) error {
	cons, err := a.consumerInGateway(ctx, gatewayID, consumerID)
	if err != nil {
		return err
	}
	pol, err := a.policyInGateway(ctx, gatewayID, policyID)
	if err != nil {
		return err
	}
	if err := a.validatePolicyProtocol(cons, pol); err != nil {
		return err
	}
	if err := a.repo.AttachPolicy(ctx, consumerID, policyID); err != nil {
		return err
	}
	a.invalidate(ctx, cons)
	a.policyCache.Delete(policyID.String())
	return nil
}

func (a *associator) validatePolicyProtocol(cons *domain.Consumer, pol *policydomain.Policy) error {
	if pol.IsGlobal() {
		return nil
	}
	if cons.Type != domain.TypeLLM && cons.Type != domain.TypeMCP {
		return nil
	}
	protocols, ok := a.resolver.SupportedProtocols(pol.Slug)
	if !ok {
		return nil
	}
	for _, protocol := range protocols {
		if protocol == string(cons.Type) {
			return nil
		}
	}
	return fmt.Errorf("%w: plugin %s does not support consumer protocol %s", domain.ErrPolicyProtocolMismatch, pol.Slug, cons.Type)
}

func (a *associator) DetachPolicy(ctx context.Context, gatewayID ids.GatewayID, consumerID ids.ConsumerID, policyID ids.PolicyID) error {
	cons, err := a.consumerInGateway(ctx, gatewayID, consumerID)
	if err != nil {
		return err
	}
	if err := a.repo.DetachPolicy(ctx, consumerID, policyID); err != nil {
		return err
	}
	a.invalidate(ctx, cons)
	a.policyCache.Delete(policyID.String())
	return nil
}

func (a *associator) consumerInGateway(ctx context.Context, gatewayID ids.GatewayID, consumerID ids.ConsumerID) (*domain.Consumer, error) {
	cons, err := a.repo.FindByID(ctx, consumerID)
	if err != nil {
		return nil, err
	}
	if cons.GatewayID != gatewayID {
		return nil, domain.ErrNotFound
	}
	return cons, nil
}

func (a *associator) registryInGateway(ctx context.Context, gatewayID ids.GatewayID, registryID ids.RegistryID) (*registrydomain.Registry, error) {
	reg, err := a.registryRepo.FindByID(ctx, registryID)
	if err != nil {
		return nil, err
	}
	if reg.GatewayID != gatewayID {
		return nil, registrydomain.ErrNotFound
	}
	return reg, nil
}

func (a *associator) roleInGateway(ctx context.Context, gatewayID ids.GatewayID, roleID ids.RoleID) error {
	role, err := a.roleRepo.FindByID(ctx, roleID)
	if err != nil {
		return err
	}
	if role.GatewayID != gatewayID {
		return roledomain.ErrNotFound
	}
	return nil
}

func (a *associator) authInGateway(ctx context.Context, gatewayID ids.GatewayID, authID ids.AuthID) (*authdomain.Auth, error) {
	au, err := a.authRepo.FindByID(ctx, authID)
	if err != nil {
		return nil, err
	}
	if au.GatewayID != gatewayID {
		return nil, authdomain.ErrNotFound
	}
	return au, nil
}

func (a *associator) policyInGateway(ctx context.Context, gatewayID ids.GatewayID, policyID ids.PolicyID) (*policydomain.Policy, error) {
	pol, err := a.policyRepo.FindByID(ctx, policyID)
	if err != nil {
		return nil, err
	}
	if pol.GatewayID != gatewayID {
		return nil, policydomain.ErrNotFound
	}
	return pol, nil
}

func (a *associator) invalidate(ctx context.Context, cons *domain.Consumer) {
	a.memoryCache.Delete(cons.ID.String())
	publishGatewayDataInvalidation(ctx, a.publisher, a.logger, cons.GatewayID)
	if a.signaler != nil {
		a.signaler.Signal(ctx)
	}
}

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

package registry

import (
	"context"
	"errors"
	"fmt"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
)

// ErrNotSharedAccount is an instance whose upstream account is not the one it
// holds for everyone: each caller connects their own, or the server is entered
// with a credential that is the same for everybody by construction.
var ErrNotSharedAccount = fmt.Errorf(
	"registry: this server does not use a shared account: %w", commonerrors.ErrConflict)

// SharedAccount is the state of the upstream account an instance holds for
// every caller.
type SharedAccount struct {
	Provider   string
	Connected  bool
	AccountRef string
	Scopes     []string
	ExpiresAt  time.Time
	// NeedsReconnect is a stored account that can no longer be used: it expired
	// with nothing to refresh it with, or the vault can no longer read it.
	NeedsReconnect bool
}

// SharedAccountLink is a connect page an admin walks to authorize the account.
type SharedAccountLink struct {
	Ticket       string
	ConsumerPath string
}

// ServerTicketMinter mints the connect ticket the admin's browser redeems. It
// is the same minter the runtime uses for a user connecting their own account;
// what makes this one the instance's is the subject it is minted for.
type ServerTicketMinter interface {
	CreateServerTicket(ctx context.Context, gatewayID ids.GatewayID, principalSub, consumerPath, code, instanceID string) (string, error)
}

//go:generate mockery --name=SharedAccountService --dir=. --output=./mocks --filename=registry_shared_account_service_mock.go --case=underscore --with-expecter
type SharedAccountService interface {
	Status(ctx context.Context, gatewayID ids.GatewayID, registryID ids.RegistryID) (*SharedAccount, error)
	Link(ctx context.Context, gatewayID ids.GatewayID, registryID ids.RegistryID) (*SharedAccountLink, error)
	Disconnect(ctx context.Context, gatewayID ids.GatewayID, registryID ids.RegistryID) error
}

type sharedAccountService struct {
	registries Finder
	vault      vaultdomain.Repository
	tickets    ServerTicketMinter
}

func NewSharedAccountService(registries Finder, vault vaultdomain.Repository, tickets ServerTicketMinter) SharedAccountService {
	return &sharedAccountService{registries: registries, vault: vault, tickets: tickets}
}

func (s *sharedAccountService) Status(
	ctx context.Context,
	gatewayID ids.GatewayID,
	registryID ids.RegistryID,
) (*SharedAccount, error) {
	reg, cfg, err := s.sharedRegistry(ctx, gatewayID, registryID)
	if err != nil {
		return nil, err
	}
	out := &SharedAccount{Provider: cfg.Provider}
	cred, err := s.vault.Find(ctx, gatewayID, domain.SharedAccountSubject(reg.ID), domain.ForwardedVaultProvider(reg))
	switch {
	case err == nil:
		out.Connected = true
		out.AccountRef = cred.AccountRef
		out.Scopes = cred.Scopes
		out.ExpiresAt = cred.ExpiresAt
		out.NeedsReconnect = cred.RefreshToken == "" && cred.Expired(0)
	case errors.Is(err, vaultdomain.ErrUndecryptable):
		// It was connected; the vault key changed under it. Saying "not
		// connected" would hide the only fact that explains the failures.
		out.Connected = true
		out.NeedsReconnect = true
	case !errors.Is(err, vaultdomain.ErrNotFound):
		return nil, err
	}
	return out, nil
}

// Link mints the connect page for the instance's own account.
//
// The subject is the instance, not the admin walking the page: what they
// authorize belongs to the server every caller reaches through, and an admin
// leaving the company must not take it with them.
func (s *sharedAccountService) Link(
	ctx context.Context,
	gatewayID ids.GatewayID,
	registryID ids.RegistryID,
) (*SharedAccountLink, error) {
	reg, _, err := s.sharedRegistry(ctx, gatewayID, registryID)
	if err != nil {
		return nil, err
	}
	if s.tickets == nil {
		return nil, fmt.Errorf("registry: connect is not available: %w", commonerrors.ErrNotFound)
	}
	code := ""
	if reg.MCPTarget != nil {
		code = reg.MCPTarget.Code
	}
	consumerPath := appconsumer.MCPPath(consumerdomain.StoreSlug)
	ticket, err := s.tickets.CreateServerTicket(
		ctx, gatewayID, domain.SharedAccountSubject(reg.ID), consumerPath, code, reg.ID.String(),
	)
	if err != nil {
		return nil, err
	}
	return &SharedAccountLink{Ticket: ticket, ConsumerPath: consumerPath}, nil
}

// Disconnect drops the account. Nothing upstream is revoked — the provider
// still holds the grant — but every call through this instance stops until it
// is connected again, which is the point of the button.
func (s *sharedAccountService) Disconnect(
	ctx context.Context,
	gatewayID ids.GatewayID,
	registryID ids.RegistryID,
) error {
	reg, _, err := s.sharedRegistry(ctx, gatewayID, registryID)
	if err != nil {
		return err
	}
	err = s.vault.Delete(ctx, gatewayID, domain.SharedAccountSubject(reg.ID), domain.ForwardedVaultProvider(reg))
	if errors.Is(err, vaultdomain.ErrNotFound) {
		return nil
	}
	return err
}

func (s *sharedAccountService) sharedRegistry(
	ctx context.Context,
	gatewayID ids.GatewayID,
	registryID ids.RegistryID,
) (*domain.Registry, *domain.MCPAuth, error) {
	reg, err := s.registries.FindByID(ctx, gatewayID, registryID)
	if err != nil {
		return nil, nil, err
	}
	cfg := reg.ForwardedAuth()
	if !cfg.Shared() {
		return nil, nil, ErrNotSharedAccount
	}
	return reg, cfg, nil
}

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

package store

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
)

// ErrSharedConnection refuses to disconnect an instance that reads one account
// for everyone: it is not the caller's to revoke, and revoking it would cut off
// every user of the instance. An administrator disconnects it in Registry.
var ErrSharedConnection = fmt.Errorf(
	"store: this server uses one account shared by everyone; an administrator disconnects it in Registry: %w",
	commonerrors.ErrConflict,
)

// PrincipalDisconnectRequest names the account one user revokes.
type PrincipalDisconnectRequest struct {
	GatewayID    ids.GatewayID
	PrincipalSub string
	// RegistryID is the instance whose account is revoked: the registry_id the
	// preview lists the connection under.
	RegistryID ids.RegistryID
}

// PrincipalDisconnector revokes the account a user linked to one Store server,
// from the Portal: what Disconnect on the server's connect page does, without
// a connect link. The next call to the server asks them to connect again.
//
//go:generate mockery --name=PrincipalDisconnector --dir=. --output=./mocks --filename=store_principal_disconnector_mock.go --case=underscore --with-expecter
type PrincipalDisconnector interface {
	Disconnect(ctx context.Context, in PrincipalDisconnectRequest) error
}

// RegistryFinder resolves one registry by id.
type RegistryFinder interface {
	FindByID(ctx context.Context, id ids.RegistryID) (*registrydomain.Registry, error)
}

type principalDisconnector struct {
	registries RegistryFinder
	installs   installationdomain.Reader
	vault      vaultdomain.Repository
	logger     *slog.Logger
}

// DisconnectorOption tunes NewPrincipalDisconnector.
type DisconnectorOption func(*principalDisconnector)

// WithDisconnectorInstalls supplies the principal's installs so a per-user
// region is revoked under the same vault key connect and dial use.
func WithDisconnectorInstalls(installs installationdomain.Reader) DisconnectorOption {
	return func(d *principalDisconnector) { d.installs = installs }
}

// NewPrincipalDisconnector wires the revoke over the registries and the vault
// the preview reads the connection from.
func NewPrincipalDisconnector(registries RegistryFinder, vault vaultdomain.Repository, logger *slog.Logger, opts ...DisconnectorOption) (PrincipalDisconnector, error) {
	if registries == nil || vault == nil {
		return nil, ErrUnavailable
	}
	if logger == nil {
		logger = slog.Default()
	}
	d := &principalDisconnector{registries: registries, vault: vault, logger: logger}
	for _, opt := range opts {
		if opt != nil {
			opt(d)
		}
	}
	return d, nil
}

// Disconnect deletes the caller's credential for the instance. One that is not
// linked is already disconnected and answers nil, so a retried or doubled
// click is not an error.
func (d *principalDisconnector) Disconnect(ctx context.Context, in PrincipalDisconnectRequest) error {
	sub := strings.TrimSpace(in.PrincipalSub)
	if in.GatewayID.IsNil() || sub == "" || in.RegistryID.IsNil() {
		return fmt.Errorf("store: gateway, principal and instance are required: %w", commonerrors.ErrValidation)
	}
	reg, err := d.registries.FindByID(ctx, in.RegistryID)
	if err != nil {
		return err
	}
	// The same sources the preview lists as connections, and only this
	// gateway's: an id from another one is a registry this caller never saw.
	if reg == nil || reg.GatewayID != in.GatewayID || forwardedAuthOf(reg) == nil {
		return registrydomain.ErrNotFound
	}
	if registrydomain.CredentialSubject(reg, sub) != sub {
		return ErrSharedConnection
	}
	config, err := d.installConfig(ctx, in.GatewayID, sub, reg)
	if err != nil {
		return err
	}
	provider := registrydomain.ForwardedVaultProviderFor(reg, config)
	if provider == "" {
		return registrydomain.ErrNotFound
	}
	switch err := d.vault.Delete(ctx, in.GatewayID, sub, provider); {
	case errors.Is(err, vaultdomain.ErrNotFound):
		return nil
	case err != nil:
		return fmt.Errorf("store: disconnect %q: %w", reg.Name, err)
	}
	d.logger.LogAttrs(ctx, slog.LevelInfo, "security audit",
		slog.String("event", "mcp_provider_unlinked"),
		slog.String("gateway_id", in.GatewayID.String()),
		slog.String("registry_id", in.RegistryID.String()),
		slog.String("provider_id", forwardedAuthOf(reg).Provider),
		slog.String("source", "portal"))
	return nil
}

func (d *principalDisconnector) installConfig(ctx context.Context, gatewayID ids.GatewayID, principalSub string, reg *registrydomain.Registry) (map[string]string, error) {
	if d.installs == nil {
		return nil, nil
	}
	installs, err := d.installs.ListByPrincipal(ctx, gatewayID, principalSub)
	if err != nil {
		return nil, fmt.Errorf("store: list installs: %w", err)
	}
	return installConfigFor(reg, installs), nil
}

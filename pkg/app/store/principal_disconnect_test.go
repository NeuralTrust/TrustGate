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
	"testing"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
	vaultmocks "github.com/NeuralTrust/TrustGate/pkg/domain/vault/mocks"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type registriesByID map[ids.RegistryID]*registrydomain.Registry

func (r registriesByID) FindByID(_ context.Context, id ids.RegistryID) (*registrydomain.Registry, error) {
	if reg, ok := r[id]; ok {
		return reg, nil
	}
	return nil, registrydomain.ErrNotFound
}

func linearOn(gw ids.GatewayID) *registrydomain.Registry {
	reg := forwardedRegistry("app.linear/mcp", "Linear", "app.linear/mcp")
	reg.GatewayID = gw
	return reg
}

// Disconnecting deletes the caller's own credential, the one the preview
// reads, and nothing else.
func TestPrincipalDisconnect_DeletesTheCallersOwnCredential(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	reg := linearOn(gw)
	vault := vaultmocks.NewRepository(t)
	vault.EXPECT().Delete(mock.Anything, gw, "alice", registrydomain.ForwardedVaultProvider(reg)).Return(nil).Once()
	d, err := NewPrincipalDisconnector(registriesByID{reg.ID: reg}, vault, nil)
	require.NoError(t, err)

	require.NoError(t, d.Disconnect(context.Background(), PrincipalDisconnectRequest{GatewayID: gw, PrincipalSub: " alice ", RegistryID: reg.ID}))
}

// A doubled click, or an account already gone, is already disconnected.
func TestPrincipalDisconnect_NothingLinkedIsAlreadyDisconnected(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	reg := linearOn(gw)
	vault := vaultmocks.NewRepository(t)
	vault.EXPECT().Delete(mock.Anything, gw, "alice", mock.Anything).Return(vaultdomain.ErrNotFound).Once()
	d, err := NewPrincipalDisconnector(registriesByID{reg.ID: reg}, vault, nil)
	require.NoError(t, err)

	require.NoError(t, d.Disconnect(context.Background(), PrincipalDisconnectRequest{GatewayID: gw, PrincipalSub: "alice", RegistryID: reg.ID}))
}

func TestPrincipalDisconnect_RefusesWithoutDeleting(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	shared := linearOn(gw)
	shared.MCPTarget.Auth.Account = registrydomain.MCPAccountShared
	foreign := linearOn(ids.New[ids.GatewayKind]())
	keyed := linearOn(gw)
	keyed.MCPTarget.Auth = nil
	regs := registriesByID{shared.ID: shared, foreign.ID: foreign, keyed.ID: keyed}

	for name, tc := range map[string]struct {
		in   PrincipalDisconnectRequest
		want error
	}{
		"a shared account":          {in: PrincipalDisconnectRequest{GatewayID: gw, PrincipalSub: "alice", RegistryID: shared.ID}, want: ErrSharedConnection},
		"another gateway's server":  {in: PrincipalDisconnectRequest{GatewayID: gw, PrincipalSub: "alice", RegistryID: foreign.ID}, want: commonerrors.ErrNotFound},
		"a server needing no login": {in: PrincipalDisconnectRequest{GatewayID: gw, PrincipalSub: "alice", RegistryID: keyed.ID}, want: commonerrors.ErrNotFound},
		"an unknown server":         {in: PrincipalDisconnectRequest{GatewayID: gw, PrincipalSub: "alice", RegistryID: ids.New[ids.RegistryKind]()}, want: commonerrors.ErrNotFound},
		"no principal":              {in: PrincipalDisconnectRequest{GatewayID: gw, PrincipalSub: " ", RegistryID: shared.ID}, want: commonerrors.ErrValidation},
	} {
		d, err := NewPrincipalDisconnector(regs, vaultmocks.NewRepository(t), nil)
		require.NoError(t, err)
		err = d.Disconnect(context.Background(), tc.in)
		require.True(t, errors.Is(err, tc.want), "%s: err = %v, want %v", name, err, tc.want)
	}
	require.ErrorIs(t, ErrSharedConnection, commonerrors.ErrConflict)
}

func TestNewPrincipalDisconnector_NeedsAVault(t *testing.T) {
	_, err := NewPrincipalDisconnector(registriesByID{}, nil, nil)
	require.ErrorIs(t, err, ErrUnavailable)
}

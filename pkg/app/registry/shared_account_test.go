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

package registry_test

import (
	"context"
	"errors"
	"testing"
	"time"

	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	appmocks "github.com/NeuralTrust/TrustGate/pkg/app/registry/mocks"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
	vaultmocks "github.com/NeuralTrust/TrustGate/pkg/domain/vault/mocks"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type recordedTicket struct {
	gatewayID    ids.GatewayID
	principalSub string
	consumerPath string
	code         string
	instanceID   string
}

type ticketRecorder struct{ last recordedTicket }

func (r *ticketRecorder) CreateServerTicket(
	_ context.Context,
	gatewayID ids.GatewayID,
	principalSub, consumerPath, code, instanceID string,
) (string, error) {
	r.last = recordedTicket{gatewayID, principalSub, consumerPath, code, instanceID}
	return "tk", nil
}

func sharedRegistry(t *testing.T, gw ids.GatewayID, account domain.MCPAccount) *domain.Registry {
	t.Helper()
	reg, err := domain.NewMCPRegistry(gw, "notion", "", &domain.MCPTarget{
		URL:  "https://mcp.notion.com/mcp",
		Code: "com.notion/mcp",
		Auth: &domain.MCPAuth{
			Mode: domain.MCPAuthModeForwarded, Provider: "notion", ClientID: "cid",
			AuthorizeURL: "https://notion/a", TokenURL: "https://notion/t",
			Account: account,
		},
	})
	require.NoError(t, err)
	return reg
}

func TestSharedAccountService(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()

	t.Run("the account belongs to the instance, not to the admin connecting it", func(t *testing.T) {
		reg := sharedRegistry(t, gw, domain.MCPAccountShared)
		finder := appmocks.NewFinder(t)
		finder.EXPECT().FindByID(mock.Anything, gw, reg.ID).Return(reg, nil).Once()
		tickets := &ticketRecorder{}
		svc := appregistry.NewSharedAccountService(finder, vaultmocks.NewRepository(t), tickets)

		link, err := svc.Link(context.Background(), gw, reg.ID)

		require.NoError(t, err)
		require.Equal(t, "tk", link.Ticket)
		// An admin who leaves must not take the server's account with them.
		require.Equal(t, domain.SharedAccountSubject(reg.ID), tickets.last.principalSub)
		require.Equal(t, reg.ID.String(), tickets.last.instanceID)
	})

	t.Run("reads the instance's own credential", func(t *testing.T) {
		reg := sharedRegistry(t, gw, domain.MCPAccountShared)
		finder := appmocks.NewFinder(t)
		finder.EXPECT().FindByID(mock.Anything, gw, reg.ID).Return(reg, nil).Once()
		vault := vaultmocks.NewRepository(t)
		vault.EXPECT().
			Find(mock.Anything, gw, domain.SharedAccountSubject(reg.ID), domain.ForwardedVaultProvider(reg)).
			Return(&vaultdomain.Credential{AccountRef: "ops@acme.com", RefreshToken: "r", ExpiresAt: time.Now().Add(time.Hour)}, nil).
			Once()
		svc := appregistry.NewSharedAccountService(finder, vault, &ticketRecorder{})

		account, err := svc.Status(context.Background(), gw, reg.ID)

		require.NoError(t, err)
		require.True(t, account.Connected)
		require.Equal(t, "ops@acme.com", account.AccountRef)
		require.False(t, account.NeedsReconnect)
	})

	t.Run("an instance whose callers connect their own has no shared account", func(t *testing.T) {
		reg := sharedRegistry(t, gw, domain.MCPAccountUser)
		finder := appmocks.NewFinder(t)
		finder.EXPECT().FindByID(mock.Anything, gw, reg.ID).Return(reg, nil).Times(3)
		svc := appregistry.NewSharedAccountService(finder, vaultmocks.NewRepository(t), &ticketRecorder{})

		_, statusErr := svc.Status(context.Background(), gw, reg.ID)
		_, linkErr := svc.Link(context.Background(), gw, reg.ID)
		disconnectErr := svc.Disconnect(context.Background(), gw, reg.ID)

		for _, err := range []error{statusErr, linkErr, disconnectErr} {
			require.ErrorIs(t, err, commonerrors.ErrConflict)
		}
	})

	// Disconnecting something already gone is what the admin asked for.
	t.Run("disconnecting twice is not an error", func(t *testing.T) {
		reg := sharedRegistry(t, gw, domain.MCPAccountShared)
		finder := appmocks.NewFinder(t)
		finder.EXPECT().FindByID(mock.Anything, gw, reg.ID).Return(reg, nil).Once()
		vault := vaultmocks.NewRepository(t)
		vault.EXPECT().
			Delete(mock.Anything, gw, domain.SharedAccountSubject(reg.ID), domain.ForwardedVaultProvider(reg)).
			Return(vaultdomain.ErrNotFound).
			Once()
		svc := appregistry.NewSharedAccountService(finder, vault, &ticketRecorder{})

		require.NoError(t, svc.Disconnect(context.Background(), gw, reg.ID))
	})

	// The vault key changed under a connected account: saying "not connected"
	// would hide the only fact that explains the failures.
	t.Run("an unreadable credential still reads as connected", func(t *testing.T) {
		reg := sharedRegistry(t, gw, domain.MCPAccountShared)
		finder := appmocks.NewFinder(t)
		finder.EXPECT().FindByID(mock.Anything, gw, reg.ID).Return(reg, nil).Once()
		vault := vaultmocks.NewRepository(t)
		vault.EXPECT().
			Find(mock.Anything, gw, mock.Anything, mock.Anything).
			Return(nil, vaultdomain.ErrUndecryptable).
			Once()
		svc := appregistry.NewSharedAccountService(finder, vault, &ticketRecorder{})

		account, err := svc.Status(context.Background(), gw, reg.ID)

		require.NoError(t, err)
		require.True(t, account.Connected)
		require.True(t, account.NeedsReconnect)
	})

	t.Run("a missing credential is simply not connected", func(t *testing.T) {
		reg := sharedRegistry(t, gw, domain.MCPAccountShared)
		finder := appmocks.NewFinder(t)
		finder.EXPECT().FindByID(mock.Anything, gw, reg.ID).Return(reg, nil).Once()
		vault := vaultmocks.NewRepository(t)
		vault.EXPECT().Find(mock.Anything, gw, mock.Anything, mock.Anything).Return(nil, vaultdomain.ErrNotFound).Once()
		svc := appregistry.NewSharedAccountService(finder, vault, &ticketRecorder{})

		account, err := svc.Status(context.Background(), gw, reg.ID)

		require.NoError(t, err)
		require.False(t, account.Connected)
		require.Equal(t, "notion", account.Provider)
		require.False(t, errors.Is(err, commonerrors.ErrConflict))
	})
}

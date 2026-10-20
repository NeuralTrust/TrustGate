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

package configsyncrevocation_test

import (
	"context"
	"errors"
	"testing"
	"time"

	appconfigsyncrevocation "github.com/NeuralTrust/TrustGate/pkg/app/configsyncrevocation"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/configsyncrevocation"
	domainmocks "github.com/NeuralTrust/TrustGate/pkg/domain/configsyncrevocation/mocks"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var revokeNow = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)

func newRevoker(store domain.Store) appconfigsyncrevocation.Revoker {
	return appconfigsyncrevocation.NewRevoker(store, func() time.Time { return revokeNow })
}

func TestRevoker_RejectsInvalidRequestsWithoutWriting(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name         string
		scope        string
		jtis         []string
		issuedBefore int64
	}{
		{name: "empty scope", scope: "", jtis: []string{"a1"}},
		{name: "no jtis and no mark", scope: "gw"},
		{name: "empty jtis and no mark", scope: "gw", jtis: []string{}},
		{name: "negative mark", scope: "gw", jtis: []string{"a1"}, issuedBefore: -1},
		{name: "mark 61 seconds ahead", scope: "gw", issuedBefore: revokeNow.Unix() + 61},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := domainmocks.NewStore(t)
			err := newRevoker(store).Revoke(context.Background(), tc.scope, tc.jtis, tc.issuedBefore)
			require.ErrorIs(t, err, commonerrors.ErrValidation)
		})
	}
}

func TestRevoker_AppliesValidRequestsOnce(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name         string
		jtis         []string
		issuedBefore int64
		want         domain.Revocation
	}{
		{
			name:         "mark exactly 60 seconds ahead is accepted",
			issuedBefore: revokeNow.Unix() + 60,
			want:         domain.Revocation{Scope: "gw", IssuedBefore: revokeNow.Unix() + 60},
		},
		{
			name: "jtis only",
			jtis: []string{"a1", "b2"},
			want: domain.Revocation{Scope: "gw", JTIs: []string{"a1", "b2"}},
		},
		{
			name: "duplicate jtis are applied once",
			jtis: []string{"a1", "b2", "a1"},
			want: domain.Revocation{Scope: "gw", JTIs: []string{"a1", "b2"}},
		},
		{
			name:         "jtis and mark in one request",
			jtis:         []string{"a1"},
			issuedBefore: 1000,
			want:         domain.Revocation{Scope: "gw", JTIs: []string{"a1"}, IssuedBefore: 1000},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := domainmocks.NewStore(t)
			store.EXPECT().Apply(mock.Anything, tc.want).Return(nil).Once()
			err := newRevoker(store).Revoke(context.Background(), "gw", tc.jtis, tc.issuedBefore)
			require.NoError(t, err)
		})
	}
}

func TestRevoker_PropagatesStoreError(t *testing.T) {
	t.Parallel()
	errBoom := errors.New("store down")
	store := domainmocks.NewStore(t)
	store.EXPECT().Apply(mock.Anything, mock.Anything).Return(errBoom).Once()
	err := newRevoker(store).Revoke(context.Background(), "gw", []string{"a1"}, 0)
	require.ErrorIs(t, err, errBoom)
}

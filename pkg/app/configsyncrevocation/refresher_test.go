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
	"sync/atomic"
	"testing"
	"time"

	appconfigsyncrevocation "github.com/NeuralTrust/TrustGate/pkg/app/configsyncrevocation"
	appmocks "github.com/NeuralTrust/TrustGate/pkg/app/configsyncrevocation/mocks"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/configsyncrevocation"
	domainmocks "github.com/NeuralTrust/TrustGate/pkg/domain/configsyncrevocation/mocks"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func storedRevocation() domain.Revocations {
	return domain.Revocations{JTIs: []domain.JTIRevocation{{Scope: "gw-1", JTI: revokedToken().JTI}}}
}

func TestRefresher_PrimeFailureStartsEmpty(t *testing.T) {
	reader := useManualReader(t)
	store := domainmocks.NewStore(t)
	store.EXPECT().Load(mock.Anything).Return(domain.Revocations{}, errors.New("db down")).Once()
	gate := appconfigsyncrevocation.NewGate(appconfigsyncrevocation.ModeEnforce, discardLogger())

	appconfigsyncrevocation.NewRefresher(store, gate, appmocks.NewStreamCloser(t), time.Minute, discardLogger()).Prime(context.Background())

	require.True(t, gate.Admit(context.Background(), revokedToken()))
	require.EqualValues(t, 1, counterSum(t, reader, appconfigsyncrevocation.RefreshMetric, map[string]string{"result": "error"}))
}

func TestRefresher_FailureKeepsTheLastSet(t *testing.T) {
	store := domainmocks.NewStore(t)
	store.EXPECT().Load(mock.Anything).Return(storedRevocation(), nil).Once()
	store.EXPECT().Load(mock.Anything).Return(domain.Revocations{}, errors.New("db down")).Maybe()
	closer := appmocks.NewStreamCloser(t)
	closer.EXPECT().CloseRevoked(mock.Anything).Return(0).Once()
	gate := appconfigsyncrevocation.NewGate(appconfigsyncrevocation.ModeEnforce, discardLogger())
	refresher := appconfigsyncrevocation.NewRefresher(store, gate, closer, 5*time.Millisecond, discardLogger())

	refresher.Prime(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	refresher.Run(ctx)

	require.True(t, gate.Revoked(revokedToken()), "a failed reload dropped the last loaded revocations")
}

func TestRefresher_EnforceClosesRevokedStreamsAfterEachLoad(t *testing.T) {
	reader := useManualReader(t)
	store := domainmocks.NewStore(t)
	store.EXPECT().Load(mock.Anything).Return(storedRevocation(), nil).Once()
	closer := appmocks.NewStreamCloser(t)
	closer.EXPECT().CloseRevoked(mock.Anything).RunAndReturn(func(isRevoked func(domain.Identity) bool) int {
		require.True(t, isRevoked(revokedToken()), "the close pass must see the snapshot just loaded")
		return 2
	}).Once()
	gate := appconfigsyncrevocation.NewGate(appconfigsyncrevocation.ModeEnforce, discardLogger())

	appconfigsyncrevocation.NewRefresher(store, gate, closer, time.Minute, discardLogger()).Prime(context.Background())

	require.EqualValues(t, 2, counterSum(t, reader, appconfigsyncrevocation.StreamsClosedMetric, nil))
	require.EqualValues(t, 1, counterSum(t, reader, appconfigsyncrevocation.RefreshMetric, map[string]string{"result": "ok"}))
}

func TestRefresher_ShadowNeverClosesStreams(t *testing.T) {
	t.Parallel()
	store := domainmocks.NewStore(t)
	store.EXPECT().Load(mock.Anything).Return(storedRevocation(), nil).Once()
	closer := appmocks.NewStreamCloser(t)
	gate := appconfigsyncrevocation.NewGate(appconfigsyncrevocation.ModeShadow, discardLogger())

	appconfigsyncrevocation.NewRefresher(store, gate, closer, time.Minute, discardLogger()).Prime(context.Background())

	closer.AssertNotCalled(t, "CloseRevoked", mock.Anything)
}

func TestRefresher_OffNeverLoads(t *testing.T) {
	t.Parallel()
	store := domainmocks.NewStore(t)
	gate := appconfigsyncrevocation.NewGate(appconfigsyncrevocation.ModeOff, discardLogger())
	refresher := appconfigsyncrevocation.NewRefresher(store, gate, appmocks.NewStreamCloser(t), time.Millisecond, discardLogger())

	refresher.Prime(context.Background())
	done := make(chan struct{})
	go func() {
		refresher.Run(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run kept running in off mode")
	}
	store.AssertNotCalled(t, "Load", mock.Anything)
}

func TestRefresher_RunReloadsUntilCancelled(t *testing.T) {
	t.Parallel()
	var loads atomic.Int32
	store := domainmocks.NewStore(t)
	store.EXPECT().Load(mock.Anything).RunAndReturn(func(context.Context) (domain.Revocations, error) {
		loads.Add(1)
		return domain.Revocations{}, nil
	})
	gate := appconfigsyncrevocation.NewGate(appconfigsyncrevocation.ModeShadow, discardLogger())
	refresher := appconfigsyncrevocation.NewRefresher(store, gate, appmocks.NewStreamCloser(t), 2*time.Millisecond, discardLogger())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		refresher.Run(ctx)
		close(done)
	}()
	require.Eventually(t, func() bool { return loads.Load() >= 2 }, time.Second, time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

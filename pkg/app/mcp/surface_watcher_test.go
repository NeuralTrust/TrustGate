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

package mcp_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
	"github.com/stretchr/testify/require"
)

type flakyCredentialLister struct {
	calls atomic.Int32
	row   *vaultdomain.Credential
}

func (l *flakyCredentialLister) ListByPrincipal(context.Context, ids.GatewayID, string) ([]*vaultdomain.Credential, error) {
	if l.calls.Add(1) == 1 {
		return nil, errors.New("temporary lookup failure")
	}
	return []*vaultdomain.Credential{l.row}, nil
}

type blockingCredentialLister struct {
	calls   atomic.Int32
	started chan struct{}
	release chan struct{}
	rows    []*vaultdomain.Credential
}

func (l *blockingCredentialLister) ListByPrincipal(context.Context, ids.GatewayID, string) ([]*vaultdomain.Credential, error) {
	if l.calls.Add(1) == 1 {
		close(l.started)
	}
	<-l.release
	return l.rows, nil
}

func TestSurfaceWatcherCoalescesConcurrentPolls(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	lister := &blockingCredentialLister{
		started: make(chan struct{}),
		release: make(chan struct{}),
		rows: []*vaultdomain.Credential{{
			GatewayID: gatewayID, PrincipalSub: "ana", Provider: "notion", UpdatedAt: time.Now(),
		}},
	}
	watcher := appmcp.NewSurfaceWatcher(lister, nil)
	consumer := &appconsumer.RoutableConsumer{Consumer: &consumerdomain.Consumer{GatewayID: gatewayID}}
	principal := &identity.Principal{Subject: "ana"}

	const callers = 12
	results := make(chan string, callers)
	var group sync.WaitGroup
	group.Add(callers)
	for range callers {
		go func() {
			defer group.Done()
			results <- watcher.WatchSnapshot(context.Background(), consumer, principal)
		}()
	}
	select {
	case <-lister.started:
	case <-time.After(time.Second):
		t.Fatal("credential lookup did not start")
	}
	close(lister.release)
	group.Wait()
	close(results)

	var first string
	for result := range results {
		if first == "" {
			first = result
		}
		require.Equal(t, first, result)
	}
	require.NotEmpty(t, first)
	require.EqualValues(t, 1, lister.calls.Load())
}

func TestSurfaceWatcherDoesNotCacheLookupFailures(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	lister := &flakyCredentialLister{row: &vaultdomain.Credential{
		GatewayID: gatewayID, PrincipalSub: "ana", Provider: "notion", UpdatedAt: time.Now(),
	}}
	watcher := appmcp.NewSurfaceWatcher(lister, nil)
	consumer := &appconsumer.RoutableConsumer{Consumer: &consumerdomain.Consumer{GatewayID: gatewayID}}
	principal := &identity.Principal{Subject: "ana"}

	require.Empty(t, watcher.WatchSnapshot(context.Background(), consumer, principal))
	require.NotEmpty(t, watcher.WatchSnapshot(context.Background(), consumer, principal))
	require.EqualValues(t, 2, lister.calls.Load())
}

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
	"sync"
	"testing"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	authmocks "github.com/NeuralTrust/TrustGate/pkg/domain/auth/mocks"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	policymocks "github.com/NeuralTrust/TrustGate/pkg/domain/policy/mocks"
	backendmocks "github.com/NeuralTrust/TrustGate/pkg/domain/registry/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type pausedConsumerSnapshot struct {
	domain.Reader
	mu       sync.Mutex
	current  *domain.Consumer
	started  chan struct{}
	release  chan struct{}
	readOnce bool
}

func (r *pausedConsumerSnapshot) ListByGateway(ctx context.Context, _ ids.GatewayID) ([]*domain.Consumer, error) {
	r.mu.Lock()
	snapshot := *r.current
	pause := !r.readOnce
	r.readOnce = true
	r.mu.Unlock()
	if pause {
		close(r.started)
		select {
		case <-r.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return []*domain.Consumer{&snapshot}, nil
}

func TestDataFinderInvalidationRejectsInflightOldBinding(t *testing.T) {
	for _, invalidate := range []string{"clear", "delete", "prefix"} {
		for _, concurrent := range []bool{false, true} {
			name := invalidate
			if concurrent {
				name += "/read_before_old_load_finishes"
			}
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				gwID := ids.New[ids.GatewayKind]()
				authID := ids.New[ids.AuthKind]()
				old := routableConsumer(gwID, nil)
				old.RegistryIDs = nil
				repo := &pausedConsumerSnapshot{current: old, started: make(chan struct{}), release: make(chan struct{})}
				var releaseOnce sync.Once
				release := func() { releaseOnce.Do(func() { close(repo.release) }) }
				t.Cleanup(release)
				policies := policymocks.NewRepository(t)
				policies.EXPECT().ListByGateway(mock.Anything, gwID).Return(nil, nil).Twice()
				auths := authmocks.NewRepository(t)
				auths.EXPECT().FindByIDs(mock.Anything, gwID, []ids.AuthID{authID}).Return([]*authdomain.Auth{{ID: authID, GatewayID: gwID}}, nil).Once()
				manager := newCacheManager()
				finder := appconsumer.NewDataFinder(repo, backendmocks.NewRepository(t), policies, auths, nil, manager, newTestLogger())
				done := make(chan error, 1)
				go func() {
					_, err := finder.FindByGateway(ctx, gwID)
					done <- err
				}()
				select {
				case <-repo.started:
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}

				updated := *old
				updated.AuthIDs = []ids.AuthID{authID}
				repo.mu.Lock()
				repo.current = &updated
				repo.mu.Unlock()
				ttl := manager.GetTTLMap(cache.ConsumerDataTTLName)
				switch invalidate {
				case "clear":
					manager.ClearAllTTLMaps()
				case "delete":
					ttl.Delete(gwID.String())
				case "prefix":
					ttl.DeleteByPrefix(gwID.String())
				}
				if concurrent {
					fresh := make(chan *appconsumer.Data, 1)
					go func() {
						data, err := finder.FindByGateway(ctx, gwID)
						if err != nil {
							fresh <- nil
							return
						}
						fresh <- data
					}()
					select {
					case data := <-fresh:
						require.NotNil(t, data)
						require.Len(t, data.Consumers, 1)
						require.Equal(t, []ids.AuthID{authID}, data.Consumers[0].Consumer.AuthIDs)
					case <-ctx.Done():
						t.Fatal("post-invalidation read joined the blocked old load")
					}
				}
				release()
				select {
				case err := <-done:
					require.NoError(t, err)
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}

				afterClear, err := finder.FindByGateway(ctx, gwID)
				require.NoError(t, err)
				require.Len(t, afterClear.Consumers, 1)
				assert.Equal(t, []ids.AuthID{authID}, afterClear.Consumers[0].Consumer.AuthIDs,
					"a load started before snapshot invalidation must not poison subsequent reads with the old binding")

			})
		}
	}
}

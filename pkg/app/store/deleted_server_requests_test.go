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
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

type fakePendingDenier struct {
	gateway ids.GatewayID
	code    string
	by      string
	err     error
}

func (f *fakePendingDenier) DenyPending(_ context.Context, gatewayID ids.GatewayID, code, by string, _ time.Time) (int64, error) {
	f.gateway, f.code, f.by = gatewayID, code, by
	return 1, f.err
}

func TestDeletedServerRequests_DeniesTheCustomServersRequests(t *testing.T) {
	gw, registryID := ids.New[ids.GatewayKind](), ids.New[ids.RegistryKind]()
	denier := &fakePendingDenier{}
	if err := NewDeletedServerRequests(denier, nil).DeleteByRegistry(context.Background(), gw, registryID); err != nil {
		t.Fatalf("DeleteByRegistry: %v", err)
	}
	if denier.gateway != gw || denier.code != registrydomain.CustomStoreCode(registryID) || denier.by != ServerDeletedActor {
		t.Fatalf("denied %+v, want the custom code of %s by %q", denier, registryID, ServerDeletedActor)
	}
}

func TestDeletedServerRequests_FailureBlocksTheDelete(t *testing.T) {
	boom := errors.New("db down")
	cleaner := NewDeletedServerRequests(&fakePendingDenier{err: boom}, nil)
	if err := cleaner.DeleteByRegistry(context.Background(), ids.New[ids.GatewayKind](), ids.New[ids.RegistryKind]()); !errors.Is(err, boom) {
		t.Fatalf("want the denier's error, got %v", err)
	}
}

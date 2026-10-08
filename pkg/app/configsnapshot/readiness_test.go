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

package configsnapshot_test

import (
	"context"
	"errors"
	"testing"

	appsnapshot "github.com/NeuralTrust/TrustGate/pkg/app/configsnapshot"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/routing/algorithm"
	infrasnapshot "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
	configsync "github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/sync"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDispatcherReadinessRequiresSuccessfulCompileWithoutLKG(t *testing.T) {
	t.Parallel()
	compiler := &readinessCompiler{}
	d := appsnapshot.NewDispatcher(compiler, infrasnapshot.NewCodec(), appsnapshot.NewHolder(), &fakeBroadcaster{}, &fakeOutbox{}, nil, appsnapshot.DispatcherConfig{})
	ctx := context.Background()
	assert.ErrorIs(t, d.Readiness(ctx), configsync.ErrNotReady)
	compiler.fail = true
	require.Error(t, d.Dispatch(ctx))
	assert.ErrorIs(t, d.Readiness(ctx), configsync.ErrNotReady)
	compiler.fail = false
	require.NoError(t, d.Dispatch(ctx))
	assert.NoError(t, d.Readiness(ctx))
	compiler.fail = true
	require.Error(t, d.Dispatch(ctx))
	assert.NoError(t, d.Readiness(ctx), "later outages must preserve the admitted snapshot")
}

type readinessCompiler struct {
	data readmodel.Data
	fail bool
}

func (c *readinessCompiler) Compile(context.Context) (*readmodel.Snapshot, error) {
	if c.fail {
		return nil, errors.New("compile failed")
	}
	return readmodel.Build(c.data), nil
}

func TestDispatcherQuarantinesNoncanonicalRoutingWithoutBlockingCompilation(t *testing.T) {
	t.Parallel()
	healthy := consumerdomain.Consumer{ID: ids.New[ids.ConsumerKind](), GatewayID: ids.New[ids.GatewayKind](), Active: true}
	legacy := consumerdomain.Consumer{
		ID: ids.New[ids.ConsumerKind](), GatewayID: ids.New[ids.GatewayKind](),
		LBConfig: &consumerdomain.LBConfig{Enabled: true, Algorithm: algorithm.SmartRouting},
	}
	compiler := &readinessCompiler{data: readmodel.Data{Consumers: []consumerdomain.Consumer{healthy, legacy}}}
	holder := appsnapshot.NewHolder()
	codec := infrasnapshot.NewCodec()
	d := appsnapshot.NewDispatcher(compiler, codec, holder, &fakeBroadcaster{}, &fakeOutbox{}, nil, appsnapshot.DispatcherConfig{})
	ctx := context.Background()
	require.NoError(t, d.Dispatch(ctx), "one inadmissible consumer must not withhold every tenant's snapshot")
	assert.NoError(t, d.Readiness(ctx))
	raw, _, loaded := holder.Snapshot()
	require.True(t, loaded)
	published, err := codec.Decode(raw)
	require.NoError(t, err)
	_, ok := published.ConsumerByID(healthy.ID)
	assert.True(t, ok, "unrelated tenants keep receiving configuration")
	quarantined, ok := published.ConsumerByID(legacy.ID)
	require.True(t, ok)
	assert.Equal(t, algorithm.SmartRouting, quarantined.LBConfig.Algorithm)
	assert.Nil(t, quarantined.LBConfig.SmartRouting, "the inadmissible ladder is withheld so only its pool fails closed")
}

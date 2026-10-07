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
	"testing"

	appsnapshot "github.com/NeuralTrust/TrustGate/pkg/app/configsnapshot"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/routing/algorithm"
	infrasnapshot "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
	configsync "github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/sync"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDispatcherReadinessRequiresSuccessfulCompileWithoutLKG(t *testing.T) {
	t.Parallel()
	compiler := &togglingCompiler{inner: newDispatchCompiler(&settableGateways{})}
	d := appsnapshot.NewDispatcher(compiler, infrasnapshot.NewCodec(), appsnapshot.NewHolder(), &fakeBroadcaster{}, &fakeOutbox{}, nil, appsnapshot.DispatcherConfig{})
	ctx := context.Background()
	assert.ErrorIs(t, d.Readiness(ctx), configsync.ErrNotReady)
	compiler.fail.Store(true)
	require.Error(t, d.Dispatch(ctx))
	assert.ErrorIs(t, d.Readiness(ctx), configsync.ErrNotReady)
	compiler.fail.Store(false)
	require.NoError(t, d.Dispatch(ctx))
	assert.NoError(t, d.Readiness(ctx))
	assert.Equal(t, appsnapshot.SourceNone, d.Source(), "compile readiness must not depend on LKG instrumentation")
	compiler.fail.Store(true)
	require.Error(t, d.Dispatch(ctx))
	assert.NoError(t, d.Readiness(ctx), "later outages must preserve the admitted snapshot")
}

type readinessCompiler struct{ data readmodel.Data }

func (c *readinessCompiler) Compile(context.Context) (*readmodel.Snapshot, error) {
	return readmodel.Build(c.data), nil
}

func TestDispatcherReadinessRejectsNoncanonicalCompilation(t *testing.T) {
	t.Parallel()
	compiler := &readinessCompiler{data: readmodel.Data{Consumers: []consumerdomain.Consumer{{
		Active: false, LBConfig: &consumerdomain.LBConfig{Enabled: false, Algorithm: algorithm.SmartRouting},
	}}}}
	holder := appsnapshot.NewHolder()
	d := appsnapshot.NewDispatcher(compiler, infrasnapshot.NewCodec(), holder, &fakeBroadcaster{}, &fakeOutbox{}, nil, appsnapshot.DispatcherConfig{})
	ctx := context.Background()
	require.Error(t, d.Dispatch(ctx), "legacy disabled routing cannot be advertised as compiled")
	assert.ErrorIs(t, d.Readiness(ctx), configsync.ErrNotReady)
	_, _, loaded := holder.Snapshot()
	assert.False(t, loaded)
	compiler.data = readmodel.Data{}
	require.NoError(t, d.Dispatch(ctx))
	assert.NoError(t, d.Readiness(ctx))
}

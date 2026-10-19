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
	"sync/atomic"
	"testing"
	"time"

	appsnapshot "github.com/NeuralTrust/TrustGate/pkg/app/configsnapshot"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	policydomain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	sessionrevocation "github.com/NeuralTrust/TrustGate/pkg/domain/sessionrevocation"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type revocationsReader struct {
	rows  []sessionrevocation.Record
	err   error
	since time.Time
	calls int
}

func (r *revocationsReader) Upsert(context.Context, string, string, string, time.Time) error {
	return nil
}

func (r *revocationsReader) ListActive(_ context.Context, since time.Time) ([]sessionrevocation.Record, error) {
	r.calls++
	r.since = since
	if r.err != nil {
		return nil, r.err
	}
	return r.rows, nil
}

type flakyRevocations struct {
	inner revocationsReader
	fail  atomic.Bool
}

func (f *flakyRevocations) Upsert(context.Context, string, string, string, time.Time) error {
	return nil
}

func (f *flakyRevocations) ListActive(ctx context.Context, since time.Time) ([]sessionrevocation.Record, error) {
	if f.fail.Load() {
		f.inner.calls++
		return nil, errors.New("db down")
	}
	return f.inner.ListActive(ctx, since)
}

func compilerWithRevocations(t *testing.T, reader sessionrevocation.Store, maxAge time.Duration) *appsnapshot.Compiler {
	t.Helper()
	acme := mustGatewayID(t, capsAcme)
	globex := mustGatewayID(t, capsGlobex)
	globexGW := gatewayWithTeam(globex, "globex")
	globexGW.Entitlements.DataPlane = gatewaydomain.DataPlaneHybrid
	return appsnapshot.NewCompiler(
		fakeGateways{items: []*gatewaydomain.Gateway{
			gatewayWithTeam(acme, "acme"),
			globexGW,
		}},
		fakeConsumers{byGateway: map[string][]*consumerdomain.Consumer{
			acme.String():   {{ID: mustConsumerID(t, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"), GatewayID: acme}},
			globex.String(): {{ID: mustConsumerID(t, "cccccccc-cccc-cccc-cccc-cccccccccccc"), GatewayID: globex}},
		}},
		fakeRegistries{byGateway: map[string][]*registrydomain.Registry{}},
		fakePolicies{byGateway: map[string][]*policydomain.Policy{}},
		fakeAuths{byGateway: map[string][]*authdomain.Auth{}},
		fakeCatalog{providers: []catalogdomain.Provider{{Code: "openai"}}},
		nil,
		appsnapshot.WithSessionRevocations(reader, maxAge),
	)
}

func revocationRows(now time.Time) []sessionrevocation.Record {
	return []sessionrevocation.Record{
		{GatewayID: capsAcme, Org: "acme", Subject: "user-1", RevokedAt: now.Add(-time.Hour)},
		{GatewayID: capsAcme, Org: "acme", Subject: "old", RevokedAt: now.Add(-40 * 24 * time.Hour)},
		{GatewayID: capsGlobex, Org: "globex", Subject: "user-2", RevokedAt: now.Add(-time.Minute)},
	}
}

func subjects(rows []readmodel.SessionRevocation) []string {
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.Subject)
	}
	return out
}

func TestCompilePutsActiveSessionRevocationsOnTheGatewayScope(t *testing.T) {
	t.Parallel()
	now := time.Now()
	reader := &revocationsReader{rows: revocationRows(now)}
	global, scoped, catalog, err := compilerWithRevocations(t, reader, 0).CompileAll(context.Background())
	require.NoError(t, err)

	assert.Empty(t, catalog.Data().SessionRevocations, "the catalog snapshot does not carry revocations")
	assert.Equal(t, []string{"user-1"}, subjects(global.Data().SessionRevocations), "the global snapshot keeps the hosted gateway and drops the hybrid one and the expired row")
	assert.Equal(t, []string{"user-1"}, subjects(scoped[capsAcme].Data().SessionRevocations))
	assert.Equal(t, []string{"user-2"}, subjects(scoped[capsGlobex].Data().SessionRevocations), "the hybrid gateway's marker travels only in its scoped snapshot")

	wantSince := now.Add(-30 * 24 * time.Hour)
	assert.WithinDuration(t, wantSince, reader.since, 2*time.Second)

	at, ok := scoped[capsGlobex].SessionRevokedAt(capsGlobex, "globex", "user-2")
	require.True(t, ok)
	assert.WithinDuration(t, now.Add(-time.Minute), at, time.Second)
	_, ok = scoped[capsAcme].SessionRevokedAt(capsGlobex, "globex", "user-2")
	assert.False(t, ok)
}

func TestCompileSessionRevocationWindowFollowsTheSessionCap(t *testing.T) {
	t.Parallel()
	now := time.Now()
	reader := &revocationsReader{rows: revocationRows(now)}
	_, scoped, _, err := compilerWithRevocations(t, reader, 90*24*time.Hour).CompileAll(context.Background())
	require.NoError(t, err)

	assert.Equal(t, []string{"old", "user-1"}, subjects(scoped[capsAcme].Data().SessionRevocations))
	assert.WithinDuration(t, now.Add(-90*24*time.Hour), reader.since, 2*time.Second)
}

func TestCompileReusesTheLastSessionRevocationsWhenTheNextReadFails(t *testing.T) {
	t.Parallel()
	reader := &flakyRevocations{inner: revocationsReader{rows: revocationRows(time.Now())}}
	c := compilerWithRevocations(t, reader, 0)

	first, err := c.CompileFor(context.Background(), capsAcme)
	require.NoError(t, err)
	require.Equal(t, []string{"user-1"}, subjects(first.Data().SessionRevocations))

	reader.fail.Store(true)
	again, err := c.CompileFor(context.Background(), capsAcme)
	require.NoError(t, err)
	assert.Equal(t, []string{"user-1"}, subjects(again.Data().SessionRevocations), "a failed read must not publish a snapshot that drops the marker")
}

func TestCompileWithoutSessionRevocationsLeavesTheSnapshotWithoutThem(t *testing.T) {
	t.Parallel()
	snap, err := twoTenantCompiler(t,
		mustGatewayID(t, capsAcme), mustGatewayID(t, capsGlobex),
		mustConsumerID(t, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"), mustConsumerID(t, "cccccccc-cccc-cccc-cccc-cccccccccccc"),
	).CompileFor(context.Background(), capsAcme)
	require.NoError(t, err)
	assert.Empty(t, snap.Data().SessionRevocations)
	_, ok := snap.SessionRevokedAt(capsAcme, "acme", "user-1")
	assert.False(t, ok)
}

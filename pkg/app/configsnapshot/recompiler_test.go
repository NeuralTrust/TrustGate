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
	"sync"
	"testing"
	"time"

	appsnapshot "github.com/NeuralTrust/TrustGate/pkg/app/configsnapshot"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	policydomain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	roledomain "github.com/NeuralTrust/TrustGate/pkg/domain/role"
	infrasnapshot "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot"
)

type settableGateways struct {
	mu    sync.Mutex
	items []*gatewaydomain.Gateway
}

func (s *settableGateways) set(items []*gatewaydomain.Gateway) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items = items
}

func (s *settableGateways) List(_ context.Context, filter gatewaydomain.ListFilter) ([]*gatewaydomain.Gateway, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if filter.Page > 1 {
		return nil, 0, nil
	}
	return s.items, len(s.items), nil
}

type recordingNotifier struct {
	mu        sync.Mutex
	published []string
	errs      []error
}

func (n *recordingNotifier) Tail(context.Context) (string, error) { return "", nil }

func (n *recordingNotifier) Watch(context.Context, string) (string, string, error) {
	return "", "", nil
}

func (n *recordingNotifier) Publish(_ context.Context, version string) (string, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	var err error
	if len(n.errs) > 0 {
		err = n.errs[0]
		n.errs = n.errs[1:]
	}
	if err != nil {
		return "", err
	}
	n.published = append(n.published, version)
	return "id", nil
}

func (n *recordingNotifier) count() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.published)
}

func newTestCompiler(gateways appsnapshot.GatewayReader) *appsnapshot.Compiler {
	return appsnapshot.NewCompiler(
		gateways,
		fakeConsumers{byGateway: map[string][]*consumerdomain.Consumer{}},
		fakeRegistries{byGateway: map[string][]*registrydomain.Registry{}},
		fakePolicies{byGateway: map[string][]*policydomain.Policy{}},
		fakeAuths{byGateway: map[string][]*authdomain.Auth{}},
		fakeRoles{byGateway: map[string][]*roledomain.Role{}},
		fakeCatalog{},
	)
}

func TestRecompilerPublishesOnChangeOnly(t *testing.T) {
	gwA := mustGatewayID(t, "11111111-1111-1111-1111-111111111111")
	gateways := &settableGateways{items: []*gatewaydomain.Gateway{{ID: gwA}}}
	compiler := newTestCompiler(gateways)
	holder := appsnapshot.NewHolder()
	notifier := &recordingNotifier{}

	r := appsnapshot.NewRecompiler(compiler, infrasnapshot.NewCodec(), holder, notifier, nil, time.Second)

	if err := r.Recompile(context.Background()); err != nil {
		t.Fatalf("first recompile: %v", err)
	}
	if notifier.count() != 1 {
		t.Fatalf("expected 1 publish after first recompile, got %d", notifier.count())
	}
	firstVersion := holder.Version()

	if err := r.Recompile(context.Background()); err != nil {
		t.Fatalf("second recompile: %v", err)
	}
	if notifier.count() != 1 {
		t.Fatalf("expected no publish when config unchanged, got %d", notifier.count())
	}

	gwB := mustGatewayID(t, "22222222-2222-2222-2222-222222222222")
	gateways.set([]*gatewaydomain.Gateway{{ID: gwA}, {ID: gwB}})
	if err := r.Recompile(context.Background()); err != nil {
		t.Fatalf("third recompile: %v", err)
	}
	if notifier.count() != 2 {
		t.Fatalf("expected publish on change, got %d", notifier.count())
	}
	if holder.Version() == firstVersion {
		t.Fatalf("expected version to change after config change")
	}
}

func TestRecompilerRetriesAfterPublishFailure(t *testing.T) {
	gwA := mustGatewayID(t, "11111111-1111-1111-1111-111111111111")
	gateways := &settableGateways{items: []*gatewaydomain.Gateway{{ID: gwA}}}
	compiler := newTestCompiler(gateways)
	holder := appsnapshot.NewHolder()
	notifier := &recordingNotifier{errs: []error{errors.New("redis down")}}

	r := appsnapshot.NewRecompiler(compiler, infrasnapshot.NewCodec(), holder, notifier, nil, time.Second)

	if err := r.Recompile(context.Background()); err == nil {
		t.Fatalf("expected error when publish fails")
	}
	if _, _, ok := holder.Snapshot(); !ok {
		t.Fatalf("holder should still hold the snapshot despite publish failure")
	}
	if notifier.count() != 0 {
		t.Fatalf("expected no successful publish, got %d", notifier.count())
	}

	if err := r.Recompile(context.Background()); err != nil {
		t.Fatalf("retry recompile: %v", err)
	}
	if notifier.count() != 1 {
		t.Fatalf("expected publish to be retried, got %d", notifier.count())
	}
}

func TestRecompilerRefreshesHolderOnRollback(t *testing.T) {
	gwA := mustGatewayID(t, "11111111-1111-1111-1111-111111111111")
	gwB := mustGatewayID(t, "22222222-2222-2222-2222-222222222222")
	gateways := &settableGateways{items: []*gatewaydomain.Gateway{{ID: gwA}}}
	compiler := newTestCompiler(gateways)
	holder := appsnapshot.NewHolder()
	notifier := &recordingNotifier{}

	r := appsnapshot.NewRecompiler(compiler, infrasnapshot.NewCodec(), holder, notifier, nil, time.Second)

	if err := r.Recompile(context.Background()); err != nil {
		t.Fatalf("first recompile: %v", err)
	}
	versionA := holder.Version()

	notifier.mu.Lock()
	notifier.errs = []error{errors.New("redis down")}
	notifier.mu.Unlock()
	gateways.set([]*gatewaydomain.Gateway{{ID: gwA}, {ID: gwB}})
	if err := r.Recompile(context.Background()); err == nil {
		t.Fatalf("expected publish failure on config change")
	}
	versionB := holder.Version()
	if versionB == versionA {
		t.Fatalf("holder should hold the new version despite publish failure")
	}

	gateways.set([]*gatewaydomain.Gateway{{ID: gwA}})
	if err := r.Recompile(context.Background()); err != nil {
		t.Fatalf("rollback recompile: %v", err)
	}
	if holder.Version() != versionA {
		t.Fatalf("holder must refresh to rolled-back version %s, got %s", versionA, holder.Version())
	}
}

func TestRecompilerCoalescesBursts(t *testing.T) {
	gwA := mustGatewayID(t, "11111111-1111-1111-1111-111111111111")
	gateways := &settableGateways{items: []*gatewaydomain.Gateway{{ID: gwA}}}
	compiler := newTestCompiler(gateways)
	holder := appsnapshot.NewHolder()
	notifier := &recordingNotifier{}

	r := appsnapshot.NewRecompiler(compiler, infrasnapshot.NewCodec(), holder, notifier, nil, 40*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = r.Run(ctx)
		close(done)
	}()

	waitFor(t, func() bool { return holder.Version() != "" }, time.Second)

	gwB := mustGatewayID(t, "22222222-2222-2222-2222-222222222222")
	gateways.set([]*gatewaydomain.Gateway{{ID: gwA}, {ID: gwB}})
	for i := 0; i < 5; i++ {
		r.Signal()
	}

	waitFor(t, func() bool { return notifier.count() == 2 }, time.Second)
	time.Sleep(120 * time.Millisecond)
	if notifier.count() != 2 {
		t.Fatalf("expected exactly 2 publishes after coalesced burst, got %d", notifier.count())
	}

	cancel()
	<-done
}

func waitFor(t *testing.T, cond func() bool, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("condition not met within %s", timeout)
}

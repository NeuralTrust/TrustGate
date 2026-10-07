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
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	appsnapshot "github.com/NeuralTrust/TrustGate/pkg/app/configsnapshot"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	infrasnapshot "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
)

// fakeLKGStore mirrors the repository's guards: Save writes only a newer row.
type fakeLKGStore struct {
	mu        sync.Mutex
	rows      map[string]appsnapshot.LKGRecord
	saved     []string
	attempts  []string
	touched   []string
	keptLast  []string
	deletes   int
	saveErr   error
	loadErr   error
	touchCall int
}

func newFakeLKGStore() *fakeLKGStore {
	return &fakeLKGStore{rows: map[string]appsnapshot.LKGRecord{}}
}

func (s *fakeLKGStore) Save(_ context.Context, rec appsnapshot.LKGRecord) (bool, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attempts = append(s.attempts, rec.Scope)
	if s.saveErr != nil {
		return false, "", s.saveErr
	}
	if cur, ok := s.rows[rec.Scope]; ok && !cur.CompiledAt.Before(rec.CompiledAt) {
		return false, cur.Version, nil
	}
	s.rows[rec.Scope] = rec
	s.saved = append(s.saved, rec.Scope)
	return true, rec.Version, nil
}

func (s *fakeLKGStore) attemptCount(scope string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, a := range s.attempts {
		if a == scope {
			n++
		}
	}
	return n
}

func (s *fakeLKGStore) Touch(_ context.Context, held []appsnapshot.LKGVersion, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.touchCall++
	for _, h := range held {
		if cur, ok := s.rows[h.Scope]; ok && cur.Version == h.Version && cur.CompiledAt.Before(at) {
			cur.CompiledAt = at
			s.rows[h.Scope] = cur
			s.touched = append(s.touched, h.Scope)
		}
	}
	return nil
}

func (s *fakeLKGStore) DeleteVanished(_ context.Context, keep []string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deletes++
	s.keptLast = append([]string(nil), keep...)
	in := map[string]bool{}
	for _, k := range keep {
		in[k] = true
	}
	for scope, rec := range s.rows {
		if !in[scope] && !rec.CompiledAt.After(at) {
			delete(s.rows, scope)
		}
	}
	return nil
}

func (s *fakeLKGStore) Load(context.Context) ([]appsnapshot.LKGRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.loadErr != nil {
		return nil, s.loadErr
	}
	out := make([]appsnapshot.LKGRecord, 0, len(s.rows))
	for _, r := range s.rows {
		out = append(out, r)
	}
	return out, nil
}

func (s *fakeLKGStore) savedScopes() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]string(nil), s.saved...)
	sort.Strings(out)
	return out
}

func (s *fakeLKGStore) resetSaved() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.saved = nil
}

func (s *fakeLKGStore) row(scope string) appsnapshot.LKGRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rows[scope]
}

func (s *fakeLKGStore) put(rec appsnapshot.LKGRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rows[rec.Scope] = rec
}

type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func lkgTestSecret(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// togglingCompiler compiles through the real compiler until told to fail, the
// way the unreadable-policy breaker fails a whole CompileAll.
type togglingCompiler struct {
	inner *appsnapshot.Compiler
	fail  atomic.Bool
}

func (c *togglingCompiler) Compile(ctx context.Context) (*readmodel.Snapshot, error) {
	if c.fail.Load() {
		return nil, errCompile
	}
	return c.inner.Compile(ctx)
}

func (c *togglingCompiler) CompileAll(ctx context.Context) (*readmodel.Snapshot, map[string]*readmodel.Snapshot, *readmodel.Snapshot, error) {
	if c.fail.Load() {
		return nil, nil, nil, errCompile
	}
	return c.inner.CompileAll(ctx)
}

type lkgHarness struct {
	t        *testing.T
	store    *fakeLKGStore
	sealer   *infrasnapshot.LKGSealer
	clock    *testClock
	gateways *settableGateways
	logs     *bytes.Buffer
}

func newLKGHarness(t *testing.T) *lkgHarness {
	t.Helper()
	sealer, err := infrasnapshot.NewLKGSealer(lkgTestSecret(t))
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}
	gwA := mustGatewayID(t, "11111111-1111-1111-1111-111111111111")
	return &lkgHarness{
		t: t, store: newFakeLKGStore(), sealer: sealer,
		clock:    &testClock{t: time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)},
		gateways: &settableGateways{items: []*gatewaydomain.Gateway{{ID: gwA}}},
		logs:     &bytes.Buffer{},
	}
}

// dispatcher builds a dispatcher over the harness; each call is a new "process"
// with an empty holder, sharing the store and the clock.
func (h *lkgHarness) dispatcher(opts ...appsnapshot.DispatcherOption) (*appsnapshot.Dispatcher, *appsnapshot.Holder, *togglingCompiler) {
	h.t.Helper()
	holder := appsnapshot.NewHolder()
	comp := &togglingCompiler{inner: newDispatchCompiler(h.gateways)}
	logger := slog.New(slog.NewTextHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	all := append([]appsnapshot.DispatcherOption{
		appsnapshot.WithLKG(h.store, h.sealer, appsnapshot.LKGConfig{MaxAge: 24 * time.Hour, Now: h.clock.Now}),
	}, opts...)
	d := appsnapshot.NewDispatcher(comp, infrasnapshot.NewCodec(), holder, &fakeBroadcaster{}, &fakeOutbox{}, logger, appsnapshot.DispatcherConfig{}, all...)
	return d, holder, comp
}

func TestLKG_PersistsOnlyChangedScopes(t *testing.T) {
	t.Parallel()
	h := newLKGHarness(t)
	d, _, _ := h.dispatcher()
	gwA := h.gateways.items[0].ID
	gwB := mustGatewayID(t, "22222222-2222-2222-2222-222222222222")

	if err := d.Dispatch(context.Background()); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	want := []string{"", gwA.String()}
	sort.Strings(want)
	if got := h.store.savedScopes(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("first compile must persist global and gwA, got %v", got)
	}

	h.store.resetSaved()
	h.clock.advance(time.Minute)
	if err := d.Dispatch(context.Background()); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if got := h.store.savedScopes(); len(got) != 0 {
		t.Fatalf("an unchanged compile must write nothing, got %v", got)
	}

	h.gateways.set([]*gatewaydomain.Gateway{{ID: gwA}, {ID: gwB}})
	h.clock.advance(time.Minute)
	if err := d.Dispatch(context.Background()); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	want = []string{"", gwB.String()}
	sort.Strings(want)
	if got := h.store.savedScopes(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("only the global and the new scope changed, got %v", got)
	}
}

func TestLKG_PersistedPayloadIsEncrypted(t *testing.T) {
	t.Parallel()
	h := newLKGHarness(t)
	d, holder, _ := h.dispatcher()
	if err := d.Dispatch(context.Background()); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	raw, version, _ := holder.Snapshot()
	row := h.store.row("")
	if row.Version != version || row.KeyID != h.sealer.KeyID() {
		t.Fatalf("row = version %q key %q, want %q / %q", row.Version, row.KeyID, version, h.sealer.KeyID())
	}
	if bytes.Equal(row.Payload, raw) || bytes.Contains(row.Payload, raw[:min(16, len(raw))]) {
		t.Fatal("the stored payload must not be the plain snapshot")
	}
}

func TestLKG_SupersededWriteIsIgnored(t *testing.T) {
	t.Parallel()
	h := newLKGHarness(t)
	// Another replica already stored a newer snapshot for the global scope.
	newer := appsnapshot.LKGRecord{Scope: "", Version: "from-other-replica", CompiledAt: h.clock.Now().Add(time.Hour), KeyID: h.sealer.KeyID(), Payload: []byte("keep")}
	h.store.put(newer)

	d, _, _ := h.dispatcher()
	if err := d.Dispatch(context.Background()); err != nil {
		t.Fatalf("a superseded write must not fail the dispatch: %v", err)
	}
	if got := h.store.row(""); got.Version != "from-other-replica" || string(got.Payload) != "keep" {
		t.Fatalf("an older compile overwrote a newer row: %+v", got)
	}
	// The stored row holds another replica's version (a clock running ahead), so
	// this replica must not mark the scope stored: it retries on the next cycle.
	before := h.store.attemptCount("")
	h.clock.advance(time.Minute)
	if err := d.Dispatch(context.Background()); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if got := h.store.attemptCount(""); got != before+1 {
		t.Fatalf("a scope held at another version must be retried next cycle, attempts %d -> %d", before, got)
	}
	// Once the stored stamp is behind this replica's clock, the retry lands.
	h.clock.advance(2 * time.Hour)
	if err := d.Dispatch(context.Background()); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if got := h.store.row(""); got.Version == "from-other-replica" {
		t.Fatal("the retry must overwrite once this compile is the newer one")
	}
}

func TestLKG_SupersededByTheSameVersionIsNotResent(t *testing.T) {
	t.Parallel()
	h := newLKGHarness(t)
	first, _, _ := h.dispatcher()
	if err := first.Dispatch(context.Background()); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	// Another replica compiled the same data a moment later.
	row := h.store.row("")
	row.CompiledAt = row.CompiledAt.Add(time.Hour)
	h.store.put(row)

	second, _, _ := h.dispatcher()
	// No Restore: the persisted map starts empty, so the first cycle tries to save.
	if err := second.Dispatch(context.Background()); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	before := h.store.attemptCount("")
	h.clock.advance(time.Minute)
	if err := second.Dispatch(context.Background()); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if got := h.store.attemptCount(""); got != before {
		t.Fatalf("a scope already stored at the same version must not be re-sent, attempts %d -> %d", before, got)
	}
}

func TestLKG_RestoreServesPersistedThenCompileFlipsToCompiled(t *testing.T) {
	t.Parallel()
	h := newLKGHarness(t)
	first, firstHolder, _ := h.dispatcher()
	if err := first.Dispatch(context.Background()); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	wantRaw, wantVersion, _ := firstHolder.Snapshot()
	gwA := h.gateways.items[0].ID
	wantScopedRaw, wantScopedVersion, ok := firstHolder.SnapshotFor(gwA.String())
	if !ok {
		t.Fatal("setup: gwA scope missing")
	}

	// The restarted admin: compile fails, as the mass-skip breaker would.
	h.clock.advance(time.Hour)
	second, holder, comp := h.dispatcher()
	comp.fail.Store(true)
	second.Restore(context.Background())
	if err := second.Readiness(context.Background()); err != nil {
		t.Fatalf("a restored LKG must keep the admin ready while compiling fails: %v", err)
	}

	if second.Source() != appsnapshot.SourcePersisted {
		t.Fatalf("source = %v, want persisted", second.Source())
	}
	raw, version, ok := holder.Snapshot()
	if !ok || version != wantVersion || !bytes.Equal(raw, wantRaw) {
		t.Fatalf("the restored global snapshot differs: ok=%v version=%q", ok, version)
	}
	sRaw, sVersion, ok := holder.SnapshotFor(gwA.String())
	if !ok || sVersion != wantScopedVersion || !bytes.Equal(sRaw, wantScopedRaw) {
		t.Fatalf("the restored scoped snapshot differs: ok=%v", ok)
	}
	if age, ok := second.SnapshotAge(); !ok || age != time.Hour {
		t.Fatalf("age = %v ok=%v, want 1h", age, ok)
	}

	// Failing dispatches keep serving the persisted snapshot and say so.
	if err := second.Dispatch(context.Background()); err == nil {
		t.Fatal("the dispatch must still report the compile failure")
	}
	if err := second.Readiness(context.Background()); err != nil {
		t.Fatalf("a failed compile after restore must keep serving the LKG: %v", err)
	}
	if _, v, _ := holder.Snapshot(); v != wantVersion || second.Source() != appsnapshot.SourcePersisted {
		t.Fatal("a failed compile must keep the persisted snapshot and source")
	}
	if !strings.Contains(h.logs.String(), "still serving the persisted config snapshot") {
		t.Fatalf("a failed dispatch while serving persisted must WARN, logs:\n%s", h.logs.String())
	}

	// The data heals: the next compile replaces it and flips the source.
	comp.fail.Store(false)
	gwB := mustGatewayID(t, "22222222-2222-2222-2222-222222222222")
	h.gateways.set([]*gatewaydomain.Gateway{{ID: gwA}, {ID: gwB}})
	h.clock.advance(time.Minute)
	if err := second.Dispatch(context.Background()); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if second.Source() != appsnapshot.SourceCompiled {
		t.Fatalf("source = %v, want compiled", second.Source())
	}
	if err := second.Readiness(context.Background()); err != nil {
		t.Fatalf("successful fresh compilation must satisfy readiness: %v", err)
	}
	if _, v, _ := holder.Snapshot(); v == wantVersion {
		t.Fatal("the compiled snapshot must replace the persisted one")
	}
	if age, _ := second.SnapshotAge(); age != 0 {
		t.Fatalf("a fresh compile has age 0, got %v", age)
	}
}

func TestLKG_RestoreThenIdenticalCompileFlipsToCompiledWithoutRewriting(t *testing.T) {
	t.Parallel()
	h := newLKGHarness(t)
	first, _, _ := h.dispatcher()
	if err := first.Dispatch(context.Background()); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	h.store.resetSaved()
	h.clock.advance(time.Minute)
	second, _, _ := h.dispatcher()
	second.Restore(context.Background())
	if err := second.Readiness(context.Background()); err != nil {
		t.Fatalf("a restored snapshot must qualify readiness before the first compile: %v", err)
	}
	if err := second.Dispatch(context.Background()); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if err := second.Readiness(context.Background()); err != nil {
		t.Fatalf("identical-version fresh compilation must qualify readiness: %v", err)
	}
	if second.Source() != appsnapshot.SourceCompiled {
		t.Fatalf("source = %v, want compiled", second.Source())
	}
	if got := h.store.savedScopes(); len(got) != 0 {
		t.Fatalf("a restored, unchanged snapshot must not be rewritten, got %v", got)
	}
}

func TestLKG_RestoreRejectsUntrustedRows(t *testing.T) {
	t.Parallel()
	gwA := "11111111-1111-1111-1111-111111111111"
	cases := []struct {
		name   string
		mutate func(h *lkgHarness, rows map[string]appsnapshot.LKGRecord)
	}{
		{"expired", func(h *lkgHarness, _ map[string]appsnapshot.LKGRecord) { h.clock.advance(25 * time.Hour) }},
		{"wrong key id", func(_ *lkgHarness, rows map[string]appsnapshot.LKGRecord) {
			r := rows[""]
			r.KeyID = "0000000000000000"
			rows[""] = r
		}},
		{"scope swap", func(_ *lkgHarness, rows map[string]appsnapshot.LKGRecord) {
			g, s := rows[""], rows[gwA]
			g.Payload, s.Payload = s.Payload, g.Payload
			rows[""], rows[gwA] = g, s
		}},
		{"version relabelled", func(_ *lkgHarness, rows map[string]appsnapshot.LKGRecord) {
			r := rows[""]
			r.Version = "someone-elses-version"
			rows[""] = r
		}},
		{"tampered payload", func(_ *lkgHarness, rows map[string]appsnapshot.LKGRecord) {
			r := rows[""]
			r.Payload = append([]byte(nil), r.Payload...)
			r.Payload[len(r.Payload)/2] ^= 0xff
			rows[""] = r
		}},
		{"checksum mismatch", func(h *lkgHarness, rows map[string]appsnapshot.LKGRecord) {
			// Validly sealed under the row's own (scope, version), but the bytes do
			// not hash to that version.
			payload, err := h.sealer.Seal("", "claimed-version", []byte("not what the version names"))
			if err != nil {
				t.Fatalf("seal: %v", err)
			}
			r := rows[""]
			r.Version, r.Payload = "claimed-version", payload
			rows[""] = r
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newLKGHarness(t)
			first, _, _ := h.dispatcher()
			if err := first.Dispatch(context.Background()); err != nil {
				t.Fatalf("dispatch: %v", err)
			}
			rows := map[string]appsnapshot.LKGRecord{"": h.store.row(""), gwA: h.store.row(gwA)}
			tc.mutate(h, rows)
			for scope, rec := range rows {
				h.store.put(rec)
				_ = scope
			}

			second, holder, comp := h.dispatcher()
			comp.fail.Store(true)
			second.Restore(context.Background())
			if second.Source() != appsnapshot.SourceNone {
				t.Fatalf("source = %v, an untrusted global row must serve nothing", second.Source())
			}
			if _, _, ok := holder.Snapshot(); ok {
				t.Fatal("the holder must stay empty")
			}
			if !strings.Contains(h.logs.String(), "rejected") {
				t.Fatalf("a rejected row must WARN, logs:\n%s", h.logs.String())
			}
		})
	}
}

func TestLKG_RestoreSkipsOnlyTheBadScopedRow(t *testing.T) {
	t.Parallel()
	h := newLKGHarness(t)
	first, firstHolder, _ := h.dispatcher()
	if err := first.Dispatch(context.Background()); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	gwA := h.gateways.items[0].ID.String()
	bad := h.store.row(gwA)
	bad.KeyID = "0000000000000000"
	h.store.put(bad)

	second, holder, comp := h.dispatcher()
	comp.fail.Store(true)
	second.Restore(context.Background())
	_, want, _ := firstHolder.Snapshot()
	if _, got, ok := holder.Snapshot(); !ok || got != want {
		t.Fatal("the good global row must still be served")
	}
	if _, _, ok := holder.SnapshotFor(gwA); ok {
		t.Fatal("the rejected scoped row must not be served")
	}
}

func TestLKG_StoreErrorsNeverFailTheDispatch(t *testing.T) {
	t.Parallel()
	h := newLKGHarness(t)
	h.store.saveErr = errors.New("db down")
	d, holder, _ := h.dispatcher()
	if err := d.Dispatch(context.Background()); err != nil {
		t.Fatalf("a persist failure must not fail the dispatch: %v", err)
	}
	if _, _, ok := holder.Snapshot(); !ok || d.Source() != appsnapshot.SourceCompiled {
		t.Fatal("the compiled snapshot must still be served")
	}
	if !strings.Contains(h.logs.String(), "persisting config snapshot failed") {
		t.Fatal("a persist failure must WARN")
	}

	// The failure is retried on the next cycle, not forgotten.
	h.store.saveErr = nil
	h.clock.advance(time.Minute)
	if err := d.Dispatch(context.Background()); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if got := h.store.savedScopes(); len(got) != 2 {
		t.Fatalf("the failed scopes must be retried once the store recovers, got %v", got)
	}

	h2 := newLKGHarness(t)
	h2.store.loadErr = errors.New("db down")
	d2, holder2, _ := h2.dispatcher()
	d2.Restore(context.Background())
	if _, _, ok := holder2.Snapshot(); ok || d2.Source() != appsnapshot.SourceNone {
		t.Fatal("a load error must leave the admin as it is today")
	}
}

func TestLKG_DeletesVanishedScopes(t *testing.T) {
	t.Parallel()
	h := newLKGHarness(t)
	d, _, _ := h.dispatcher()
	gwA := h.gateways.items[0].ID
	if err := d.Dispatch(context.Background()); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	h.gateways.set([]*gatewaydomain.Gateway{})
	h.clock.advance(time.Minute)
	if err := d.Dispatch(context.Background()); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if got := h.store.row(gwA.String()); got.Scope != "" || got.Version != "" {
		t.Fatalf("the vanished scope must be deleted, row still there: %+v", got)
	}
}

func TestLKG_TouchKeepsUnchangedSnapshotFromAgingOut(t *testing.T) {
	t.Parallel()
	h := newLKGHarness(t)
	d, _, _ := h.dispatcher()
	if err := d.Dispatch(context.Background()); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	start := h.store.row("").CompiledAt

	h.clock.advance(10 * time.Minute)
	if err := d.Dispatch(context.Background()); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if !h.store.row("").CompiledAt.Equal(start) {
		t.Fatal("the age must not be refreshed on every cycle")
	}
	h.clock.advance(2 * time.Hour)
	if err := d.Dispatch(context.Background()); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if !h.store.row("").CompiledAt.After(start) {
		t.Fatal("an unchanged snapshot must have its age refreshed past the touch interval")
	}
	if got := h.store.savedScopes(); len(got) != 2 {
		t.Fatalf("a touch must not rewrite payloads, got %v", got)
	}
}

func TestLKG_DisabledKeepsTodaysBehaviour(t *testing.T) {
	t.Parallel()
	gwA := mustGatewayID(t, "11111111-1111-1111-1111-111111111111")
	gateways := &settableGateways{items: []*gatewaydomain.Gateway{{ID: gwA}}}
	holder := appsnapshot.NewHolder()
	d := appsnapshot.NewDispatcher(newDispatchCompiler(gateways), infrasnapshot.NewCodec(), holder, &fakeBroadcaster{}, &fakeOutbox{}, nil, appsnapshot.DispatcherConfig{})

	d.Restore(context.Background())
	if _, _, ok := holder.Snapshot(); ok {
		t.Fatal("without the feature nothing is restored")
	}
	if err := d.Dispatch(context.Background()); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if _, _, ok := holder.Snapshot(); !ok {
		t.Fatal("the compiled snapshot is served as before")
	}
	if d.Source() != appsnapshot.SourceNone {
		t.Fatalf("source = %v, want none (untracked) with the feature off", d.Source())
	}
}

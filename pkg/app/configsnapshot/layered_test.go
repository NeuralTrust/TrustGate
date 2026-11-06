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
	"log/slog"
	"strings"
	"sync"
	"testing"

	appsnapshot "github.com/NeuralTrust/TrustGate/pkg/app/configsnapshot"
	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport"
	infrasnapshot "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot"
	"github.com/stretchr/testify/require"
)

func layeredOf(digests ...byte) appsnapshot.Layered {
	l := appsnapshot.Layered{Fragments: map[[32]byte][]byte{}, Scoped: map[string]configsyncport.Manifest{}}
	for _, d := range digests {
		var digest [32]byte
		digest[0] = d
		l.Fragments[digest] = []byte{d}
		l.Global.Fragments = append(l.Global.Fragments, configsyncport.FragmentRef{Digest: digest, Size: 1})
	}
	l.Global.Version = "m1:" + string(rune('a'+digests[0]))
	return l
}

func TestHolderServesTheFragmentsOfOnePreviousPublish(t *testing.T) {
	t.Parallel()
	h := appsnapshot.NewHolder()
	if _, ok := h.ManifestFor(""); ok {
		t.Fatal("an empty holder must have no layered manifest")
	}
	h.SetLayered(layeredOf(1))
	h.SetLayered(layeredOf(2))
	for _, d := range []byte{1, 2} {
		if _, ok := h.FragmentFor("", [32]byte{d}); !ok {
			t.Fatalf("fragment %d must still be served one publish later", d)
		}
	}
	h.SetLayered(layeredOf(3))
	if _, ok := h.FragmentFor("", [32]byte{1}); ok {
		t.Fatal("a fragment two publishes old must no longer be served")
	}
	if m, ok := h.ManifestFor(""); !ok || m.Version != layeredOf(3).Global.Version {
		t.Fatalf("manifest = %q ok=%v, want the latest", m.Version, ok)
	}
	h.ClearLayered()
	if _, ok := h.ManifestFor(""); ok {
		t.Fatal("a cleared holder must have no layered manifest")
	}
	if _, ok := h.FragmentFor("", [32]byte{3}); ok {
		t.Fatal("a cleared holder must serve no fragment")
	}
}

func TestHolderServesAFragmentOnlyToScopesWhoseManifestNamesIt(t *testing.T) {
	t.Parallel()
	own := [32]byte{10}
	other := [32]byte{20}
	shared := [32]byte{30}
	manifest := func(digests ...[32]byte) configsyncport.Manifest {
		m := configsyncport.Manifest{Version: "m1:x"}
		for _, d := range digests {
			m.Fragments = append(m.Fragments, configsyncport.FragmentRef{Digest: d, Size: 1})
		}
		return m
	}
	h := appsnapshot.NewHolder()
	h.SetLayered(appsnapshot.Layered{
		Global: manifest(shared),
		Scoped: map[string]configsyncport.Manifest{
			"x": manifest(own, shared),
			"y": manifest(other, shared),
		},
		Fragments: map[[32]byte][]byte{own: {1}, other: {2}, shared: {3}},
	})

	for _, tc := range []struct {
		scope  string
		digest [32]byte
		want   bool
	}{
		{"x", own, true},
		{"x", shared, true},
		{"x", other, false},
		{"y", own, false},
		{"", shared, true},
		{"", own, false},
		{"unknown", shared, false},
	} {
		_, ok := h.FragmentFor(tc.scope, tc.digest)
		require.Equal(t, tc.want, ok, "scope %q digest %x", tc.scope, tc.digest[0])
	}

	h.SetLayered(appsnapshot.Layered{Scoped: map[string]configsyncport.Manifest{}, Fragments: map[[32]byte][]byte{}})
	_, ok := h.FragmentFor("x", own)
	require.True(t, ok, "the previous manifest of a scope still serves its fragments")
	_, ok = h.FragmentFor("x", other)
	require.False(t, ok, "the previous generation keeps the same scope boundaries")
}

type layeredBroadcast struct {
	scope, version, layered string
}

type recordingLayeredBroadcaster struct {
	fakeBroadcaster
	mu     sync.Mutex
	events []layeredBroadcast
}

func (b *recordingLayeredBroadcaster) BroadcastScopeLayered(scope, version, layered string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.events = append(b.events, layeredBroadcast{scope: scope, version: version, layered: layered})
}

func (b *recordingLayeredBroadcaster) last(scope string) (layeredBroadcast, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for i := len(b.events) - 1; i >= 0; i-- {
		if b.events[i].scope == scope {
			return b.events[i], true
		}
	}
	return layeredBroadcast{}, false
}

func TestIncrementalDispatchPublishesLayeredManifestsAndNotifiesBoth(t *testing.T) {
	w := newWorld(t, 21)
	for range 3 {
		w.addGateway()
	}
	outbox := &fakeOutbox{}
	w.outboxes = append(w.outboxes, outbox)
	holder := appsnapshot.NewHolder()
	broadcaster := &recordingLayeredBroadcaster{}
	compiler := w.compiler()
	d := appsnapshot.NewDispatcher(compiler, infrasnapshot.NewCodec(), holder, broadcaster, outbox,
		slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)), appsnapshot.DispatcherConfig{},
		appsnapshot.WithIncrementalCompile(infrasnapshot.NewFragments(), compiler))
	ctx := context.Background()

	check := func(label string) {
		t.Helper()
		global, ok := holder.ManifestFor("")
		require.True(t, ok, "%s: a compile through the fragment encoder publishes a layered manifest", label)
		require.True(t, strings.HasPrefix(global.Version, infrasnapshot.LayeredVersionPrefix), label)
		for _, ref := range global.Fragments {
			_, ok := holder.FragmentFor("", ref.Digest)
			require.True(t, ok, "%s: every fragment of the manifest is served", label)
		}
		event, ok := broadcaster.last("")
		require.True(t, ok, label)
		require.Equal(t, holder.Version(), event.version, "%s: single-blob data planes are notified of the single-blob version", label)
		require.Equal(t, global.Version, event.layered, "%s: layered data planes are notified of the manifest version", label)
		for _, g := range w.gatewayList() {
			manifest, ok := holder.ManifestFor(g.ID.String())
			require.True(t, ok, "%s: every gateway scope has a manifest", label)
			if event, ok := broadcaster.last(g.ID.String()); ok {
				_, version, _ := holder.SnapshotFor(g.ID.String())
				require.Equal(t, version, event.version, label)
				require.Equal(t, manifest.Version, event.layered, label)
			}
		}
	}

	require.NoError(t, d.Dispatch(ctx))
	check("boot")
	for range 10 {
		label := w.step()
		require.NoError(t, d.Dispatch(ctx), label)
		check(label)
	}
}

func TestFullDispatchPublishesNoLayeredManifest(t *testing.T) {
	w := newWorld(t, 22)
	w.addGateway()
	d, holder := w.dispatcher(false, nil, appsnapshot.DispatcherConfig{})
	require.NoError(t, d.Dispatch(context.Background()))
	_, ok := holder.ManifestFor("")
	require.False(t, ok, "without the fragment encoder there is no layered snapshot, so data planes pull the single blob")
}

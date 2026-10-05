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

package consumer

import (
	"fmt"
	"sync"
	"testing"
	"time"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func routable(slug string, active bool) RoutableConsumer {
	return RoutableConsumer{
		Consumer: &domain.Consumer{
			ID:        ids.New[ids.ConsumerKind](),
			GatewayID: ids.New[ids.GatewayKind](),
			Slug:      slug,
			Active:    active,
		},
	}
}

func TestData_MatchSlug(t *testing.T) {
	t.Parallel()
	d := NewData(ids.New[ids.GatewayKind](), []RoutableConsumer{routable("X84Yhsy8", true)})

	if _, ok := d.MatchSlug("X84Yhsy8"); !ok {
		t.Fatal("MatchSlug on known slug returned ok=false")
	}
	if _, ok := d.MatchSlug("unknown1"); ok {
		t.Fatal("MatchSlug on unknown slug returned ok=true")
	}
}

func TestData_MatchSlug_SkipsInactiveConsumers(t *testing.T) {
	t.Parallel()
	d := NewData(ids.New[ids.GatewayKind](), []RoutableConsumer{routable("X84Yhsy8", false)})

	if _, ok := d.MatchSlug("X84Yhsy8"); ok {
		t.Fatal("inactive consumer must not be routable")
	}
}

func mcpRegistry(gatewayID ids.GatewayID) *registrydomain.Registry {
	return &registrydomain.Registry{
		ID:        ids.New[ids.RegistryKind](),
		GatewayID: gatewayID,
		Type:      registrydomain.TypeMCP,
		Enabled:   true,
	}
}

func TestData_EffectiveRegistries_ReturnsConsumerRegistries(t *testing.T) {
	t.Parallel()
	gatewayID := ids.New[ids.GatewayKind]()
	reg := mcpRegistry(gatewayID)
	rc := routable("inline1x", true)
	rc.Registries = []*registrydomain.Registry{reg}
	d := NewData(gatewayID, []RoutableConsumer{rc})

	got := d.EffectiveRegistries(&d.Consumers[0])
	if len(got) != 1 || got[0].ID != reg.ID {
		t.Fatalf("EffectiveRegistries = %v, want [%s]", got, reg.ID)
	}
}

var storeDay0 = time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)

func grant(level domain.GrantLevel, priority, day int) domain.AuthLink {
	return domain.AuthLink{Level: level, Priority: priority, GrantedAt: storeDay0.AddDate(0, 0, day)}
}

func personalRoutable(slug string, active bool, key ids.AuthID, link domain.AuthLink) RoutableConsumer {
	rc := routable(slug, active)
	rc.Consumer.Type = domain.TypeLLM
	rc.Consumer.Audience = domain.AudiencePersonal
	rc.Consumer.AuthIDs = []ids.AuthID{key}
	rc.Consumer.AuthLinks = map[ids.AuthID]domain.AuthLink{key: link}
	return rc
}

func linkedConsumerIDs(links []StoreLink) []ids.ConsumerID {
	out := make([]ids.ConsumerID, 0, len(links))
	for _, l := range links {
		out = append(out, l.Consumer.Consumer.ID)
	}
	return out
}

func TestData_StoreLinksOrder(t *testing.T) {
	t.Parallel()
	key := ids.New[ids.AuthKind]()
	p1 := personalRoutable("pslug001", true, key, grant(domain.GrantLevelGroup, 2, 1))
	p2 := personalRoutable("pslug002", true, key, grant(domain.GrantLevelGroup, 1, 3))
	p3 := personalRoutable("pslug003", true, key, grant(domain.GrantLevelAll, 0, 0))
	p4 := personalRoutable("pslug004", true, key, grant(domain.GrantLevelUser, 5, 9))
	d := NewData(ids.New[ids.GatewayKind](), []RoutableConsumer{p1, p2, p3, p4})

	links := d.StoreLinks(key)
	require.Equal(t, []ids.ConsumerID{p4.Consumer.ID, p2.Consumer.ID, p1.Consumer.ID, p3.Consumer.ID}, linkedConsumerIDs(links))
	require.Same(t, &d.Consumers[3], links[0].Consumer)
	require.Equal(t, len(links), cap(links), "an append by a reader must not reach the shared array")
	require.Equal(t, grant(domain.GrantLevelUser, 5, 9), links[0].Link)
	require.True(t, d.HasPersonalConsumers())
}

func TestData_StoreLinksTieBreaks(t *testing.T) {
	t.Parallel()
	key := ids.New[ids.AuthKind]()
	older := personalRoutable("pslug001", true, key, grant(domain.GrantLevelGroup, 1, 1))
	newer := personalRoutable("pslug002", true, key, grant(domain.GrantLevelGroup, 1, 2))
	lowID := personalRoutable("pslug003", true, key, grant(domain.GrantLevelGroup, 1, 5))
	highID := personalRoutable("pslug004", true, key, grant(domain.GrantLevelGroup, 1, 5))
	lowID.Consumer.ID = ids.From[ids.ConsumerKind](uuid.MustParse("00000000-0000-7000-8000-000000000001"))
	highID.Consumer.ID = ids.From[ids.ConsumerKind](uuid.MustParse("00000000-0000-7000-8000-000000000002"))
	d := NewData(ids.New[ids.GatewayKind](), []RoutableConsumer{highID, newer, lowID, older})

	require.Equal(t,
		[]ids.ConsumerID{older.Consumer.ID, newer.Consumer.ID, lowID.Consumer.ID, highID.Consumer.ID},
		linkedConsumerIDs(d.StoreLinks(key)))
}

func TestData_StoreLinksLeaveOutInactiveAndUnlinked(t *testing.T) {
	t.Parallel()
	key := ids.New[ids.AuthKind]()
	inactive := personalRoutable("pslug001", false, key, grant(domain.GrantLevelUser, 1, 0))
	active := personalRoutable("pslug002", true, key, grant(domain.GrantLevelGroup, 1, 0))
	unlinked := ids.New[ids.AuthKind]()
	active.Consumer.AuthIDs = append(active.Consumer.AuthIDs, unlinked)
	d := NewData(ids.New[ids.GatewayKind](), []RoutableConsumer{inactive, active, routable("app00001", true)})

	require.Equal(t, []ids.ConsumerID{active.Consumer.ID}, linkedConsumerIDs(d.StoreLinks(key)))
	require.Empty(t, d.StoreLinks(unlinked))
	require.Empty(t, d.StoreLinks(ids.New[ids.AuthKind]()))
	require.True(t, d.HasPersonalConsumers())
}

func TestData_HasPersonalConsumers(t *testing.T) {
	t.Parallel()
	key := ids.New[ids.AuthKind]()
	cases := map[string]struct {
		data *Data
		want bool
	}{
		"nil data":         {data: nil},
		"zero data":        {data: &Data{}},
		"application only": {data: NewData(ids.New[ids.GatewayKind](), []RoutableConsumer{routable("app00001", true)})},
		"only inactive personal consumers": {data: NewData(ids.New[ids.GatewayKind](), []RoutableConsumer{
			personalRoutable("pslug001", false, key, grant(domain.GrantLevelUser, 1, 0)),
		})},
		"an active personal consumer without links": {data: NewData(ids.New[ids.GatewayKind](), []RoutableConsumer{
			{Consumer: &domain.Consumer{ID: ids.New[ids.ConsumerKind](), Slug: "pslug002", Active: true, Audience: domain.AudiencePersonal}},
		}), want: true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, tc.data.HasPersonalConsumers())
			require.Empty(t, tc.data.StoreLinks(key))
		})
	}
}

func TestData_MatchSlug_SkipsPersonalConsumers(t *testing.T) {
	t.Parallel()
	key := ids.New[ids.AuthKind]()
	personal := personalRoutable("pslug001", true, key, grant(domain.GrantLevelUser, 1, 0))
	reg := mcpRegistry(personal.Consumer.GatewayID)
	personal.Registries = []*registrydomain.Registry{reg}
	d := NewData(personal.Consumer.GatewayID, []RoutableConsumer{personal, routable("app00001", true)})

	_, ok := d.MatchSlug("pslug001")
	require.False(t, ok, "a personal consumer must not be slug-routable")
	_, ok = d.MatchSlug("app00001")
	require.True(t, ok)
	_, ok = d.RegistryByID(reg.ID)
	require.True(t, ok, "a personal consumer's registries stay indexed for the store")
}

func TestData_StoreLinksConcurrentReaders(t *testing.T) {
	t.Parallel()
	key := ids.New[ids.AuthKind]()
	consumers := make([]RoutableConsumer, 0, 10)
	for i := range 10 {
		level := []domain.GrantLevel{domain.GrantLevelUser, domain.GrantLevelGroup, domain.GrantLevelAll}[i%3]
		consumers = append(consumers, personalRoutable(fmt.Sprintf("pslug%03d", i), true, key, grant(level, i%4, 10-i)))
	}
	d := NewData(ids.New[ids.GatewayKind](), consumers)
	want := linkedConsumerIDs(d.StoreLinks(key))
	require.Len(t, want, 10)

	const readers = 64
	got := make([][]ids.ConsumerID, readers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for r := range readers {
		wg.Go(func() {
			<-start
			for range 50 {
				if !d.HasPersonalConsumers() {
					return
				}
				_ = append(d.StoreLinks(key), StoreLink{})
				got[r] = linkedConsumerIDs(d.StoreLinks(key))
			}
		})
	}
	close(start)
	wg.Wait()
	for r := range readers {
		require.Equal(t, want, got[r], "reader %d", r)
	}
}

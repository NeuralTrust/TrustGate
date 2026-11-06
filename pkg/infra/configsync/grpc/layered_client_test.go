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

package grpc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	appsnapshot "github.com/NeuralTrust/TrustGate/pkg/app/configsnapshot"
	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	infrasnapshot "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot"
	snapshotpb "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot/proto"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
	configsync "github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/sync"
)

type layeredFake struct {
	mu         sync.Mutex
	blob       []byte
	blobVer    string
	layered    bool
	manifest   configsyncport.Manifest
	fragments  map[[32]byte][]byte
	corrupt    map[[32]byte]bool
	gone       map[[32]byte]int
	served     int64
	snapshotOK bool
}

func newLayeredFake(frags [][]byte) *layeredFake {
	f := &layeredFake{corrupt: map[[32]byte]bool{}, gone: map[[32]byte]int{}}
	f.publish(frags)
	return f
}

func (f *layeredFake) publish(frags [][]byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.layered = true
	f.manifest, f.fragments = manifestOf(frags)
	f.blob = bytes.Join(frags, nil)
	f.blobVer = infrasnapshot.NewCodec().Version(f.blob)
}

func manifestOf(frags [][]byte) (configsyncport.Manifest, map[[32]byte][]byte) {
	h := sha256.New()
	store := make(map[[32]byte][]byte, len(frags))
	refs := make([]configsyncport.FragmentRef, 0, len(frags))
	for _, frag := range frags {
		digest := sha256.Sum256(frag)
		store[digest] = frag
		_, _ = h.Write(digest[:])
		refs = append(refs, configsyncport.FragmentRef{Digest: digest, Size: len(frag)})
	}
	return configsyncport.Manifest{Version: layeredVersionPrefix + hex.EncodeToString(h.Sum(nil)), Fragments: refs}, store
}

func (f *layeredFake) SnapshotPartsFor(string) ([][]byte, string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.snapshotOK = true
	return [][]byte{f.blob}, f.blobVer, true
}

func (f *layeredFake) ManifestFor(string) (configsyncport.Manifest, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.manifest, f.layered
}

func (f *layeredFake) FragmentFor(_ string, digest [32]byte) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.gone[digest] > 0 {
		f.gone[digest]--
		return nil, false
	}
	raw, ok := f.fragments[digest]
	if ok && f.corrupt[digest] {
		raw = append(bytes.Clone(raw), 'x')
	}
	f.served += int64(len(raw))
	return raw, ok
}

func (f *layeredFake) stats() (served int64, snapshot bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.served, f.snapshotOK
}

func (f *layeredFake) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.served, f.snapshotOK = 0, false
}

func layeredClient(t *testing.T, source SnapshotSource) *Client {
	t.Helper()
	lis, _ := newBufServer(t, NewService(NewHub(discardLogger(), nil), source, discardLogger(), nil))
	client := dialClient(t, lis, "dp-layered")
	client.layered = true
	return client
}

func frags(n int, tag string) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		out[i] = []byte(fmt.Sprintf("%s-fragment-%04d-%s", tag, i, bytes.Repeat([]byte("p"), 100)))
	}
	return out
}

func TestLayeredFetchAssemblesManifestOrderAndThenFetchesOnlyWhatChanged(t *testing.T) {
	parts := frags(8, "a")
	source := newLayeredFake(parts)
	client := layeredClient(t, source)

	raw, version, notModified, err := client.Fetch(context.Background(), "")
	if err != nil || notModified {
		t.Fatalf("first fetch: err=%v notModified=%v", err, notModified)
	}
	if !bytes.Equal(raw, bytes.Join(parts, nil)) || version != source.manifest.Version {
		t.Fatalf("first fetch assembled %d bytes under %q, want the manifest-order concatenation under %q", len(raw), version, source.manifest.Version)
	}
	if !client.Verifies(version) {
		t.Fatal("a layered version fetched by the client must be reported as verified")
	}
	full, _ := source.stats()

	if _, _, notModified, err := client.Fetch(context.Background(), version); err != nil || !notModified {
		t.Fatalf("fetch at the applied version: err=%v notModified=%v, want not modified", err, notModified)
	}

	source.reset()
	changed := append([][]byte(nil), parts...)
	changed[3] = []byte("a-fragment-0003-changed")
	source.publish(changed)
	raw, version, _, err = client.Fetch(context.Background(), version)
	if err != nil {
		t.Fatalf("second fetch: %v", err)
	}
	if !bytes.Equal(raw, bytes.Join(changed, nil)) || version != source.manifest.Version {
		t.Fatal("second fetch must assemble the new manifest")
	}
	if served, _ := source.stats(); served != int64(len(changed[3])) {
		t.Fatalf("second fetch pulled %d bytes, want only the changed fragment (%d of %d)", served, len(changed[3]), full)
	}
}

func TestLayeredFetchFallsBackToTheSingleBlobWhenNoManifestIsServed(t *testing.T) {
	source := &fakeSource{}
	source.set([]byte("single-blob"), "v-blob")
	client := layeredClient(t, source)

	raw, version, _, err := client.Fetch(context.Background(), "")
	if err != nil || string(raw) != "single-blob" || version != "v-blob" {
		t.Fatalf("fetch against a control plane without layered snapshots: raw=%q version=%q err=%v", raw, version, err)
	}
	if client.Verifies(version) {
		t.Fatal("a single-blob version must still be verified by the worker")
	}
}

func TestLayeredFetchFallsBackPerCallWhileNoLayeredSnapshotIsPublished(t *testing.T) {
	parts := frags(3, "b")
	source := newLayeredFake(parts)
	source.layered = false
	client := layeredClient(t, source)

	if _, version, _, err := client.Fetch(context.Background(), ""); err != nil || version != source.blobVer {
		t.Fatalf("fetch with no published manifest: version=%q err=%v, want the single-blob version", version, err)
	}
	source.publish(parts)
	if _, version, _, err := client.Fetch(context.Background(), ""); err != nil || version != source.manifest.Version {
		t.Fatalf("fetch once a manifest is published: version=%q err=%v, want the manifest version", version, err)
	}
}

func TestLayeredFetchRejectsAFragmentThatDoesNotMatchItsDigest(t *testing.T) {
	parts := frags(4, "c")
	source := newLayeredFake(parts)
	source.corrupt[sha256.Sum256(parts[2])] = true
	client := layeredClient(t, source)

	_, _, _, err := client.Fetch(context.Background(), "")
	if !errors.Is(err, configsync.ErrIntegrity) {
		t.Fatalf("fetch with a corrupt fragment: err=%v, want ErrIntegrity", err)
	}
	if _, ok := client.fragments.get(sha256.Sum256(parts[0])); ok {
		t.Fatal("a rejected pull must not update the fragment cache")
	}
}

func TestLayeredFetchRejectsAManifestWhoseVersionIsNotItsDigestHash(t *testing.T) {
	source := newLayeredFake(frags(2, "d"))
	source.manifest.Version = layeredVersionPrefix + hex.EncodeToString(make([]byte, 32))
	client := layeredClient(t, source)

	if _, _, _, err := client.Fetch(context.Background(), ""); !errors.Is(err, configsync.ErrIntegrity) {
		t.Fatalf("fetch with a forged manifest version: err=%v, want ErrIntegrity", err)
	}
}

func TestLayeredFetchRestartsFromTheManifestWhenAFragmentAgedOut(t *testing.T) {
	parts := frags(4, "e")
	source := newLayeredFake(parts)
	source.gone[sha256.Sum256(parts[1])] = 1
	client := layeredClient(t, source)

	raw, version, _, err := client.Fetch(context.Background(), "")
	if err != nil || version != source.manifest.Version || !bytes.Equal(raw, bytes.Join(parts, nil)) {
		t.Fatalf("fetch after one NotFound: version=%q err=%v, want the layered snapshot", version, err)
	}
	if _, usedBlob := source.stats(); usedBlob {
		t.Fatal("one NotFound must restart from the manifest, not fall back to the single blob")
	}
}

func TestLayeredFetchFallsBackToTheSingleBlobWhenFragmentsKeepAgingOut(t *testing.T) {
	parts := frags(4, "f")
	source := newLayeredFake(parts)
	source.gone[sha256.Sum256(parts[1])] = 2
	client := layeredClient(t, source)

	raw, version, _, err := client.Fetch(context.Background(), "")
	if err != nil || version != source.blobVer || !bytes.Equal(raw, bytes.Join(parts, nil)) {
		t.Fatalf("fetch after two NotFounds: version=%q err=%v, want the single blob", version, err)
	}
}

func TestLayeredFetchBatchesMoreFragmentsThanOneCallAllows(t *testing.T) {
	parts := frags(maxFragmentsPerRequest+10, "g")
	source := newLayeredFake(parts)
	client := layeredClient(t, source)

	raw, version, _, err := client.Fetch(context.Background(), "")
	if err != nil || version != source.manifest.Version || !bytes.Equal(raw, bytes.Join(parts, nil)) {
		t.Fatalf("fetch of %d fragments: version=%q err=%v", len(parts), version, err)
	}
}

func TestLayeredFetchKeepsVerifiedFragmentsWhenOneAgesOut(t *testing.T) {
	parts := frags(maxFragmentsPerRequest+10, "k")
	source := newLayeredFake(parts)
	source.gone[sha256.Sum256(parts[maxFragmentsPerRequest+5])] = 1
	client := layeredClient(t, source)

	raw, _, _, err := client.Fetch(context.Background(), "")
	if err != nil || !bytes.Equal(raw, bytes.Join(parts, nil)) {
		t.Fatalf("fetch after a fragment aged out: err=%v", err)
	}
	firstBatch := int64(len(bytes.Join(parts[:maxFragmentsPerRequest], nil)))
	if served, _ := source.stats(); served >= 2*firstBatch {
		t.Fatalf("served %d bytes, want less than %d: the retry must not fetch the first batch again", served, 2*firstBatch)
	}
}

func TestLayeredFetchCachesFragmentsInsideTheAssembledSnapshot(t *testing.T) {
	parts := frags(8, "s")
	client := layeredClient(t, newLayeredFake(parts))

	raw, _, _, err := client.Fetch(context.Background(), "")
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	offset := 0
	for _, part := range parts {
		cached, ok := client.fragments.get(sha256.Sum256(part))
		if !ok || len(cached) == 0 || &cached[0] != &raw[offset] {
			t.Fatalf("fragment at offset %d is cached as a separate copy, want a slice of the assembled snapshot", offset)
		}
		offset += len(part)
	}
}

type abandonedFragmentsServer struct {
	snapshotpb.UnimplementedConfigSyncServer
	manifest  *snapshotpb.Manifest
	bad       []byte
	cancelled chan struct{}
}

func (s *abandonedFragmentsServer) GetManifest(context.Context, *snapshotpb.GetManifestRequest) (*snapshotpb.Manifest, error) {
	return s.manifest, nil
}

func (s *abandonedFragmentsServer) GetFragments(req *snapshotpb.GetFragmentsRequest, stream snapshotpb.ConfigSync_GetFragmentsServer) error {
	digest := req.GetDigests()[0]
	for {
		if err := stream.Send(&snapshotpb.FragmentChunk{Digest: digest, Data: s.bad, Last: true}); err != nil {
			close(s.cancelled)
			return err
		}
		select {
		case <-stream.Context().Done():
			close(s.cancelled)
			return stream.Context().Err()
		case <-time.After(time.Millisecond):
		}
	}
}

func TestLayeredFetchEndsTheFragmentStreamWhenItGivesUp(t *testing.T) {
	good := []byte("the fragment the manifest names")
	manifest, _ := manifestOf([][]byte{good})
	refs := make([]*snapshotpb.FragmentRef, len(manifest.Fragments))
	for i, ref := range manifest.Fragments {
		refs[i] = &snapshotpb.FragmentRef{Digest: ref.Digest[:], Size: int64(ref.Size)}
	}
	server := &abandonedFragmentsServer{
		manifest:  &snapshotpb.Manifest{Version: manifest.Version, Fragments: refs},
		bad:       []byte("not the fragment"),
		cancelled: make(chan struct{}),
	}
	lis, _ := newBufServer(t, server)
	client := dialClient(t, lis, "dp-abandon")
	client.layered = true

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, _, _, err := client.Fetch(ctx, ""); !errors.Is(err, configsync.ErrIntegrity) {
		t.Fatalf("fetch = %v, want ErrIntegrity for a fragment that does not match its digest", err)
	}
	select {
	case <-server.cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("the server stream is still open after the client gave up on it")
	}
}

func TestHelloAdvertisesLayeredOnlyWhenLayeredPullIsOn(t *testing.T) {
	for _, layered := range []bool{false, true} {
		server := &helloCapture{hello: make(chan *snapshotpb.Hello, 1)}
		lis, _ := newBufServer(t, server)
		client := dialClient(t, lis, "dp-hello")
		client.layered = layered
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		go func() { _, _ = client.Watch(ctx) }()
		select {
		case hello := <-server.hello:
			if hello.GetAcceptsLayered() != layered {
				t.Fatalf("layered pull %v sent accepts_layered=%v", layered, hello.GetAcceptsLayered())
			}
		case <-ctx.Done():
			t.Fatal("no Hello received")
		}
		cancel()
	}
}

type helloCapture struct {
	snapshotpb.UnimplementedConfigSyncServer
	hello chan *snapshotpb.Hello
}

func (s *helloCapture) Sync(stream snapshotpb.ConfigSync_SyncServer) error {
	msg, err := stream.Recv()
	if err != nil {
		return err
	}
	s.hello <- msg.GetHello()
	<-stream.Context().Done()
	return stream.Context().Err()
}

type countingHolder struct {
	*appsnapshot.Holder
	mu     sync.Mutex
	served int64
}

func (h *countingHolder) FragmentFor(scope string, digest [32]byte) ([]byte, bool) {
	raw, ok := h.Holder.FragmentFor(scope, digest)
	h.mu.Lock()
	h.served += int64(len(raw))
	h.mu.Unlock()
	return raw, ok
}

func (h *countingHolder) take() int64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	served := h.served
	h.served = 0
	return served
}

func publishAssembly(t *testing.T, holder *appsnapshot.Holder, fragments *infrasnapshot.Fragments) appsnapshot.Assembled {
	t.Helper()
	assembled, err := fragments.Assemble(appsnapshot.SharedInputs{})
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	global := append(append([]byte(nil), assembled.Global...), assembled.Catalog...)
	holder.SetPartitioned(global, infrasnapshot.NewCodec().Version(global), nil)
	holder.SetLayered(assembled.Layered)
	return assembled
}

func TestLayeredFetchOfOneNewConsumerInABigGatewayPullsAFewBuckets(t *testing.T) {
	gateway := gatewaydomain.Gateway{
		ID: ids.New[ids.GatewayKind](), Slug: "big", Status: "active",
		Entitlements: gatewaydomain.Entitlements{DataPlane: gatewaydomain.DataPlaneHosted},
	}
	data := readmodel.Data{Registries: []registrydomain.Registry{{ID: ids.New[ids.RegistryKind](), GatewayID: gateway.ID, Name: "registry", Enabled: true}}}
	addPair := func(i int) {
		data.Consumers = append(data.Consumers, consumerdomain.Consumer{
			ID: ids.New[ids.ConsumerKind](), GatewayID: gateway.ID, Name: fmt.Sprintf("agent-%d", i), Slug: fmt.Sprintf("agent-%d", i), Active: true,
		})
		data.Auths = append(data.Auths, authdomain.Auth{
			ID: ids.New[ids.AuthKind](), GatewayID: gateway.ID, Name: fmt.Sprintf("key-%d", i), Enabled: true, KeyHash: fmt.Sprintf("%064x", i),
		})
	}
	for i := 0; i < 5000; i++ {
		addPair(i)
	}
	fragments := infrasnapshot.NewFragments()
	copied := data
	if err := fragments.Rebuild([]gatewaydomain.Gateway{gateway}, map[ids.GatewayID]*readmodel.Data{gateway.ID: &copied}, readmodel.Data{}); err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	holder := &countingHolder{Holder: appsnapshot.NewHolder()}
	before := publishAssembly(t, holder.Holder, fragments)
	client := layeredClient(t, holder)

	_, version, _, err := client.Fetch(context.Background(), "")
	if err != nil || version != before.Layered.Global.Version {
		t.Fatalf("first fetch: version=%q err=%v", version, err)
	}
	firstBytes := holder.take()

	addPair(5000)
	if err := fragments.Put(gateway, data); err != nil {
		t.Fatalf("put: %v", err)
	}
	after := publishAssembly(t, holder.Holder, fragments)
	raw, version, _, err := client.Fetch(context.Background(), version)
	if err != nil || version != after.Layered.Global.Version {
		t.Fatalf("second fetch: version=%q err=%v", version, err)
	}
	if _, err := infrasnapshot.NewCodec().Decode(raw); err != nil {
		t.Fatalf("decode the assembled layered snapshot: %v", err)
	}
	secondBytes := holder.take()
	t.Logf("gateway with 5000 consumers and keys: first pull %d bytes in %d fragments; one new consumer and key pulled %d bytes",
		firstBytes, len(after.Layered.Global.Fragments), secondBytes)
	if secondBytes*20 > firstBytes {
		t.Fatalf("one new consumer pulled %d of %d bytes, want a few buckets", secondBytes, firstBytes)
	}
}

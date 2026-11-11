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
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport"
	appcsr "github.com/NeuralTrust/TrustGate/pkg/app/configsyncrevocation"
	"github.com/NeuralTrust/TrustGate/pkg/domain/configsyncrevocation"
	snapshotpb "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/status"
)

type fakeLayeredSource struct {
	fakeSource
	mu        sync.Mutex
	manifests map[string]configsyncport.Manifest
	fragments map[[32]byte][]byte
}

func (f *fakeLayeredSource) ManifestFor(scope string) (configsyncport.Manifest, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, ok := f.manifests[scope]
	return m, ok
}

func (f *fakeLayeredSource) FragmentFor(scope string, digest [32]byte) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, ref := range f.manifests[scope].Fragments {
		if ref.Digest == digest {
			raw, ok := f.fragments[digest]
			return raw, ok
		}
	}
	return nil, false
}

func newFakeLayeredSource(version string, fragments ...[]byte) *fakeLayeredSource {
	src := &fakeLayeredSource{manifests: map[string]configsyncport.Manifest{}, fragments: map[[32]byte][]byte{}}
	src.set(bytes.Join(fragments, nil), "v1-blob")
	m := configsyncport.Manifest{Version: version}
	for _, raw := range fragments {
		digest := sha256.Sum256(raw)
		src.fragments[digest] = raw
		m.Fragments = append(m.Fragments, configsyncport.FragmentRef{Digest: digest, Size: len(raw)})
	}
	src.manifests[""] = m
	return src
}

func dialRaw(t *testing.T, lis interface {
	DialContext(context.Context) (net.Conn, error)
}, opts ...grpc.DialOption) snapshotpb.ConfigSyncClient {
	t.Helper()
	opts = append([]grpc.DialOption{
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}, opts...)
	conn, err := grpc.NewClient("passthrough:///bufnet", opts...)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return snapshotpb.NewConfigSyncClient(conn)
}

func TestService_GetManifestIsUnimplementedWithoutALayeredSource(t *testing.T) {
	src := &fakeSource{}
	src.set([]byte("blob"), "v1")
	lis, _ := newBufServer(t, NewService(NewHub(discardLogger(), nil), src, discardLogger(), nil))
	_, err := dialRaw(t, lis).GetManifest(context.Background(), &snapshotpb.GetManifestRequest{})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("GetManifest = %v, want Unimplemented so the data plane falls back to GetSnapshot", err)
	}
}

func TestService_GetManifestIsUnimplementedUntilALayeredSnapshotIsPublished(t *testing.T) {
	src := &fakeLayeredSource{manifests: map[string]configsyncport.Manifest{}}
	src.set([]byte("blob"), "v1")
	lis, _ := newBufServer(t, NewService(NewHub(discardLogger(), nil), src, discardLogger(), nil))
	_, err := dialRaw(t, lis).GetManifest(context.Background(), &snapshotpb.GetManifestRequest{})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("GetManifest = %v, want Unimplemented", err)
	}
}

func TestService_GetManifestReturnsTheManifestOrNotModified(t *testing.T) {
	src := newFakeLayeredSource("m1:abc", []byte("first"), []byte("second"))
	lis, _ := newBufServer(t, NewService(NewHub(discardLogger(), nil), src, discardLogger(), nil))
	client := dialRaw(t, lis)

	m, err := client.GetManifest(context.Background(), &snapshotpb.GetManifestRequest{})
	if err != nil {
		t.Fatalf("GetManifest: %v", err)
	}
	if m.GetVersion() != "m1:abc" || m.GetNotModified() || len(m.GetFragments()) != 2 {
		t.Fatalf("manifest = %v, want version m1:abc with 2 fragments", m)
	}
	want := sha256.Sum256([]byte("first"))
	if !bytes.Equal(m.GetFragments()[0].GetDigest(), want[:]) || m.GetFragments()[0].GetSize() != 5 {
		t.Fatalf("first ref = %x/%d, want the digest and size of its bytes", m.GetFragments()[0].GetDigest(), m.GetFragments()[0].GetSize())
	}

	m, err = client.GetManifest(context.Background(), &snapshotpb.GetManifestRequest{AppliedVersion: "m1:abc"})
	if err != nil {
		t.Fatalf("GetManifest: %v", err)
	}
	if !m.GetNotModified() || len(m.GetFragments()) != 0 {
		t.Fatalf("manifest = %v, want not_modified with no fragments", m)
	}
}

func readFragments(t *testing.T, stream snapshotpb.ConfigSync_GetFragmentsClient) (map[[32]byte][]byte, int, error) {
	t.Helper()
	out := map[[32]byte][]byte{}
	chunks := 0
	var current []byte
	for {
		chunk, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return out, chunks, nil
		}
		if err != nil {
			return out, chunks, err
		}
		chunks++
		current = append(current, chunk.GetData()...)
		if chunk.GetLast() {
			var digest [32]byte
			copy(digest[:], chunk.GetDigest())
			out[digest] = current
			current = nil
		}
	}
}

func TestService_GetFragmentsStreamsEveryRequestedFragmentInChunks(t *testing.T) {
	big := bytes.Repeat([]byte("fragment "), (5*snapshotChunkSize)/18)
	small := []byte("small")
	src := newFakeLayeredSource("m1:x", big, small, []byte{})
	lis, _ := newBufServer(t, NewService(NewHub(discardLogger(), nil), src, discardLogger(), nil))
	recorder := &compressionRecorder{}
	client := dialRaw(t, lis, grpc.WithStatsHandler(recorder))

	bigDigest, smallDigest := sha256.Sum256(big), sha256.Sum256(small)
	stream, err := client.GetFragments(context.Background(), &snapshotpb.GetFragmentsRequest{Digests: [][]byte{bigDigest[:], smallDigest[:]}})
	if err != nil {
		t.Fatalf("GetFragments: %v", err)
	}
	got, chunks, err := readFragments(t, stream)
	if err != nil {
		t.Fatalf("read fragments: %v", err)
	}
	if !bytes.Equal(got[bigDigest], big) || !bytes.Equal(got[smallDigest], small) {
		t.Fatalf("reassembled fragments differ from the served bytes")
	}
	if want := (len(big)+snapshotChunkSize-1)/snapshotChunkSize + 1; chunks != want {
		t.Fatalf("got %d chunks, want %d (at most %d bytes each)", chunks, want, snapshotChunkSize)
	}
	if compression := recorder.get(); compression != gzip.Name {
		t.Fatalf("fragment stream compression = %q, want gzip", compression)
	}
}

func TestService_GetFragmentsFailsWithNotFoundBeforeSendingAnything(t *testing.T) {
	src := newFakeLayeredSource("m1:x", []byte("known"))
	lis, _ := newBufServer(t, NewService(NewHub(discardLogger(), nil), src, discardLogger(), nil))
	known := sha256.Sum256([]byte("known"))
	unknown := sha256.Sum256([]byte("evicted"))
	stream, err := dialRaw(t, lis).GetFragments(context.Background(), &snapshotpb.GetFragmentsRequest{Digests: [][]byte{known[:], unknown[:]}})
	if err != nil {
		t.Fatalf("GetFragments: %v", err)
	}
	got, chunks, err := readFragments(t, stream)
	if status.Code(err) != codes.NotFound {
		t.Fatalf("GetFragments = %v, want NotFound", err)
	}
	if chunks != 0 || len(got) != 0 {
		t.Fatalf("sent %d chunks before failing, want none", chunks)
	}
}

func TestService_GetFragmentsRejectsAMalformedDigest(t *testing.T) {
	src := newFakeLayeredSource("m1:x", []byte("known"))
	lis, _ := newBufServer(t, NewService(NewHub(discardLogger(), nil), src, discardLogger(), nil))
	stream, err := dialRaw(t, lis).GetFragments(context.Background(), &snapshotpb.GetFragmentsRequest{Digests: [][]byte{[]byte("short")}})
	if err != nil {
		t.Fatalf("GetFragments: %v", err)
	}
	if _, _, err := readFragments(t, stream); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("GetFragments = %v, want InvalidArgument", err)
	}
}

type fragmentRecorder struct {
	grpc.ServerStream
	ctx     context.Context
	chunks  int
	onChunk func(chunks int)
}

func (r *fragmentRecorder) Context() context.Context { return r.ctx }

func (r *fragmentRecorder) Send(*snapshotpb.FragmentChunk) error {
	r.chunks++
	r.onChunk(r.chunks)
	return nil
}

func TestService_GetFragmentsServesOnlyTheCallersScope(t *testing.T) {
	own, other := []byte("own fragment"), []byte("other tenant fragment")
	src := newFakeLayeredSource("m1:global")
	ownDigest, otherDigest := sha256.Sum256(own), sha256.Sum256(other)
	src.fragments[ownDigest], src.fragments[otherDigest] = own, other
	src.manifests["gw-x"] = configsyncport.Manifest{Version: "m1:x", Fragments: []configsyncport.FragmentRef{{Digest: ownDigest, Size: len(own)}}}
	src.manifests["gw-y"] = configsyncport.Manifest{Version: "m1:y", Fragments: []configsyncport.FragmentRef{{Digest: otherDigest, Size: len(other)}}}
	svc := NewService(NewHub(discardLogger(), nil), src, discardLogger(), nil)

	fetch := func(scope string, digest [32]byte) error {
		stream := &fragmentRecorder{ctx: WithScope(context.Background(), scope), onChunk: func(int) {}}
		return svc.GetFragments(&snapshotpb.GetFragmentsRequest{Digests: [][]byte{digest[:]}}, stream)
	}
	if err := fetch("gw-x", ownDigest); err != nil {
		t.Fatalf("own fragment: %v", err)
	}
	if err := fetch("gw-x", otherDigest); status.Code(err) != codes.NotFound {
		t.Fatalf("another scope's fragment = %v, want NotFound", err)
	}
	if err := fetch("", otherDigest); status.Code(err) != codes.NotFound {
		t.Fatalf("a scoped fragment through the global scope = %v, want NotFound", err)
	}
}

func TestService_GetFragmentsStopsWhenTokenIsRevokedMidTransfer(t *testing.T) {
	gate := appcsr.NewGate(appcsr.ModeEnforce, discardLogger())
	big := make([]byte, 3*snapshotChunkSize)
	big[0] = 1
	src := newFakeLayeredSource("m1:x", big)
	src.manifests["gw-1"] = src.manifests[""]
	svc := NewService(NewHub(discardLogger(), nil), src, discardLogger(), gate)
	id := configsyncrevocation.Identity{Scope: "gw-1", JTI: "old", IssuedAt: 100, Signed: true, InstanceScoped: true}
	stream := &fragmentRecorder{
		ctx: WithIdentity(WithScope(context.Background(), id.Scope), id),
		onChunk: func(chunks int) {
			if chunks == 1 {
				gate.Replace(configsyncrevocation.NewSnapshot(revokedJTI("gw-1", "old")))
			}
		},
	}
	digest := sha256.Sum256(big)
	err := svc.GetFragments(&snapshotpb.GetFragmentsRequest{Digests: [][]byte{digest[:]}}, stream)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("GetFragments = %v, want Unauthenticated once the token is revoked", err)
	}
	if stream.chunks != 1 {
		t.Fatalf("sent %d chunks, want 1: the transfer must stop at the next chunk", stream.chunks)
	}
}

func openHelloSync(t *testing.T, client snapshotpb.ConfigSyncClient, hello *snapshotpb.Hello) snapshotpb.ConfigSync_SyncClient {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	stream, err := client.Sync(ctx)
	if err != nil {
		t.Fatalf("open sync: %v", err)
	}
	if err := stream.Send(&snapshotpb.ClientMessage{Msg: &snapshotpb.ClientMessage_Hello{Hello: hello}}); err != nil {
		t.Fatalf("send hello: %v", err)
	}
	return stream
}

func nextNotice(t *testing.T, stream snapshotpb.ConfigSync_SyncClient) *snapshotpb.VersionNotice {
	t.Helper()
	got := make(chan *snapshotpb.ServerMessage, 1)
	go func() {
		msg, err := stream.Recv()
		if err != nil {
			got <- nil
			return
		}
		got <- msg
	}()
	select {
	case msg := <-got:
		if msg.GetNotice() == nil {
			t.Fatalf("want a version notice, got %v", msg)
		}
		return msg.GetNotice()
	case <-time.After(2 * time.Second):
		t.Fatal("no notice received")
		return nil
	}
}

func TestService_SyncNotifiesEachDataPlaneOfTheVersionItPulls(t *testing.T) {
	src := newFakeLayeredSource("m1:first", []byte("a"))
	hub := NewHub(discardLogger(), nil)
	lis, _ := newBufServer(t, NewService(hub, src, discardLogger(), nil))
	client := dialRaw(t, lis)

	legacy := openHelloSync(t, client, &snapshotpb.Hello{InstanceId: "old-dp"})
	layered := openHelloSync(t, client, &snapshotpb.Hello{InstanceId: "new-dp", AcceptsLayered: true})

	if n := nextNotice(t, legacy); n.GetVersion() != "v1-blob" || n.GetLayered() {
		t.Fatalf("a data plane without accepts_layered got %v, want the single-blob version", n)
	}
	if n := nextNotice(t, layered); n.GetVersion() != "m1:first" || !n.GetLayered() {
		t.Fatalf("a layered data plane got %v, want the manifest version", n)
	}

	eventually(t, func() bool { return hub.ConnectionCount() == 2 }, "both streams register")
	hub.BroadcastScopeLayered("", "v2-blob", "m1:second")
	if n := nextNotice(t, legacy); n.GetVersion() != "v2-blob" || n.GetLayered() {
		t.Fatalf("legacy data plane got %v, want v2-blob", n)
	}
	if n := nextNotice(t, layered); n.GetVersion() != "m1:second" || !n.GetLayered() {
		t.Fatalf("layered data plane got %v, want m1:second", n)
	}

	hub.BroadcastScope("", "v3-blob")
	if n := nextNotice(t, layered); n.GetVersion() != "v3-blob" || n.GetLayered() {
		t.Fatalf("a publish without a layered snapshot must send the single-blob version to everyone, got %v", n)
	}
}

func TestService_SyncDoesNotRenotifyALayeredDataPlaneThatIsCurrent(t *testing.T) {
	src := newFakeLayeredSource("m1:current", []byte("a"))
	hub := NewHub(discardLogger(), nil)
	lis, _ := newBufServer(t, NewService(hub, src, discardLogger(), nil))
	stream := openHelloSync(t, dialRaw(t, lis), &snapshotpb.Hello{InstanceId: "dp", AcceptsLayered: true, LastAppliedVersion: "m1:current"})
	eventually(t, func() bool { return hub.ConnectionCount() == 1 }, "stream registers")
	hub.BroadcastScopeLayered("", "v9-blob", "m1:next")
	if n := nextNotice(t, stream); n.GetVersion() != "m1:next" {
		t.Fatalf("first notice = %v, want only the broadcast, not a renotify of the current manifest", n)
	}
}

func TestService_SyncTreatsAcceptsLayeredAsLegacyWithoutALayeredSource(t *testing.T) {
	src := &fakeSource{}
	src.set([]byte("blob"), "v1")
	lis, _ := newBufServer(t, NewService(NewHub(discardLogger(), nil), src, discardLogger(), nil))
	stream := openHelloSync(t, dialRaw(t, lis), &snapshotpb.Hello{InstanceId: "dp", AcceptsLayered: true})
	if n := nextNotice(t, stream); n.GetVersion() != "v1" || n.GetLayered() {
		t.Fatalf("notice = %v, want the single-blob version", n)
	}
}

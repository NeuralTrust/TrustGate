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
	"context"
	"io"
	"testing"
	"time"

	snapshotpb "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot/proto"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const withRef = `{"llm_target":{"auth":{"api_key":"secret://vault/openai#key"}}}`

func TestContainsSecretRef(t *testing.T) {
	cases := map[string]bool{
		withRef:                       true,
		`"SeCrEt://vault/x"`:          true,
		`https://api.openai.com/v1`:   false,
		`secret:/vault`:               false,
		`://`:                         false,
		`notsecret`:                   false,
		`xx://yy secret://z`:          true,
		"":                            false,
		`ecret://` + "`" + `secret:/`: false,
	}
	for in, want := range cases {
		if got := containsSecretRef([]byte(in)); got != want {
			t.Errorf("containsSecretRef(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestPartsHaveRef_FindsAReferenceSplitAcrossParts(t *testing.T) {
	raw := []byte(withRef)
	for at := 1; at < len(raw); at++ {
		if !partsHaveRef([][]byte{raw[:at], raw[at:]}) {
			t.Fatalf("reference split at %d not found", at)
		}
	}
	if partsHaveRef([][]byte{[]byte("plain"), []byte("bytes")}) {
		t.Fatal("parts without a reference reported as holding one")
	}
}

func refusedForSecretRefs(t *testing.T, err error) {
	t.Helper()
	st := status.Convert(err)
	if st.Code() != codes.FailedPrecondition {
		t.Fatalf("err = %v, want FailedPrecondition", err)
	}
	for _, d := range st.Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok && info.GetReason() == ReasonSecretRefsUnsupported {
			return
		}
	}
	t.Fatalf("err = %v, want ErrorInfo reason %s", err, ReasonSecretRefsUnsupported)
}

func getSnapshot(client snapshotpb.ConfigSyncClient, req *snapshotpb.GetSnapshotRequest) (*snapshotpb.SnapshotHeader, error) {
	stream, err := client.GetSnapshot(context.Background(), req)
	if err != nil {
		return nil, err
	}
	first, err := stream.Recv()
	if err != nil {
		return nil, err
	}
	for {
		if _, err := stream.Recv(); err == io.EOF {
			return first.GetHeader(), nil
		} else if err != nil {
			return nil, err
		}
	}
}

func TestService_GetSnapshotWithholdsReferencesFromAnOldDataPlane(t *testing.T) {
	src := &fakeSource{}
	src.set([]byte(withRef), "v-refs")
	lis, _ := newBufServer(t, NewService(NewHub(discardLogger(), nil), src, discardLogger(), nil))
	client := dialRaw(t, lis)

	_, err := getSnapshot(client, &snapshotpb.GetSnapshotRequest{InstanceId: "old"})
	refusedForSecretRefs(t, err)
	_, err = getSnapshot(client, &snapshotpb.GetSnapshotRequest{InstanceId: "old", AppliedVersion: "v-refs"})
	refusedForSecretRefs(t, err)

	header, err := getSnapshot(client, &snapshotpb.GetSnapshotRequest{InstanceId: "new", AcceptsSecretRefs: true})
	if err != nil || header.GetVersion() != "v-refs" {
		t.Fatalf("capable data plane got %v, %v; want the snapshot", header, err)
	}

	src.set([]byte(`{"llm_target":{"auth":{"api_key":"sk-literal"}}}`), "v-plain")
	header, err = getSnapshot(client, &snapshotpb.GetSnapshotRequest{InstanceId: "old"})
	if err != nil || header.GetVersion() != "v-plain" {
		t.Fatalf("old data plane got %v, %v once the references are gone; want the snapshot", header, err)
	}
}

func TestService_GetManifestWithholdsReferencesFromAnOldDataPlane(t *testing.T) {
	src := newFakeLayeredSource("m1:refs", []byte("plain"), []byte(withRef))
	lis, _ := newBufServer(t, NewService(NewHub(discardLogger(), nil), src, discardLogger(), nil))
	client := dialRaw(t, lis)

	_, err := client.GetManifest(context.Background(), &snapshotpb.GetManifestRequest{InstanceId: "old"})
	refusedForSecretRefs(t, err)
	m, err := client.GetManifest(context.Background(), &snapshotpb.GetManifestRequest{InstanceId: "new", AcceptsSecretRefs: true})
	if err != nil || m.GetVersion() != "m1:refs" {
		t.Fatalf("capable data plane got %v, %v; want the manifest", m, err)
	}
}

// noticeReader reads a Sync stream from a single goroutine, so a test can
// wait for a notice or for its absence without two concurrent Recv calls.
type noticeReader chan *snapshotpb.VersionNotice

func readNotices(stream snapshotpb.ConfigSync_SyncClient) noticeReader {
	ch := make(noticeReader, 8)
	go func() {
		defer close(ch)
		for {
			msg, err := stream.Recv()
			if err != nil {
				return
			}
			if n := msg.GetNotice(); n != nil {
				ch <- n
			}
		}
	}()
	return ch
}

func (r noticeReader) next(t *testing.T) *snapshotpb.VersionNotice {
	t.Helper()
	select {
	case n := <-r:
		return n
	case <-time.After(2 * time.Second):
		t.Fatal("no notice received")
		return nil
	}
}

func (r noticeReader) none(t *testing.T) {
	t.Helper()
	select {
	case n := <-r:
		t.Fatalf("old data plane got %v, want no notice", n)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestService_SyncWithholdsNoticesOfVersionsWithReferences(t *testing.T) {
	src := &fakeSource{}
	src.set([]byte(withRef), "v1")
	hub := NewHub(discardLogger(), nil)
	lis, _ := newBufServer(t, NewService(hub, src, discardLogger(), nil))
	client := dialRaw(t, lis)

	old := readNotices(openHelloSync(t, client, &snapshotpb.Hello{InstanceId: "old"}))
	capable := readNotices(openHelloSync(t, client, &snapshotpb.Hello{InstanceId: "new", AcceptsSecretRefs: true}))
	if n := capable.next(t); n.GetVersion() != "v1" {
		t.Fatalf("capable data plane got %v, want v1", n)
	}
	eventually(t, func() bool { return hub.ConnectionCount() == 2 }, "both streams register")
	old.none(t)

	src.set([]byte(withRef+" "), "v2")
	hub.BroadcastScope("", "v2")
	if n := capable.next(t); n.GetVersion() != "v2" {
		t.Fatalf("capable data plane got %v, want v2", n)
	}
	old.none(t)

	src.set([]byte("plain"), "v3")
	hub.Broadcast("v3")
	if n := old.next(t); n.GetVersion() != "v3" {
		t.Fatalf("old data plane got %v, want v3 once the references are gone", n)
	}
}

func TestService_SyncWithholdsLayeredNoticesOfManifestsWithReferences(t *testing.T) {
	src := newFakeLayeredSource("m1:refs", []byte(withRef))
	hub := NewHub(discardLogger(), nil)
	lis, _ := newBufServer(t, NewService(hub, src, discardLogger(), nil))
	old := readNotices(openHelloSync(t, dialRaw(t, lis), &snapshotpb.Hello{InstanceId: "old", AcceptsLayered: true}))
	eventually(t, func() bool { return hub.ConnectionCount() == 1 }, "stream registers")
	old.none(t)
}

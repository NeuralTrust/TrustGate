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
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/NeuralTrust/TrustGate/pkg/domain/configsyncrevocation"
	"github.com/NeuralTrust/TrustGate/pkg/domain/dataplane"
	snapshotpb "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot/proto"
)

func TestService_SyncRecordsHeartbeatSentAfterHello(t *testing.T) {
	store := &recordingStore{}
	hub := NewHub(discardLogger(), store)
	lis, _ := newBufServer(t, NewService(hub, &fakeSource{}, discardLogger(), nil))
	client := dialClient(t, lis, "dp-1")
	client.SetHeartbeat(dataplane.Heartbeat{
		Version:            "v0.64.0",
		Region:             "eu-west-1",
		DeploymentType:     "self-hosted",
		TrustGuardBaseURL:  "https://trustguard.eu.example.com",
		TrustGuardClientID: "tgc_eu",
	})

	go func() { _, _ = client.Watch(context.Background()) }()

	eventually(t, func() bool { return len(store.heartbeatsSnapshot()) == 1 }, "heartbeat after Hello never recorded")
	got := store.heartbeatsSnapshot()[0]
	want := dataplane.Heartbeat{
		Version:            "/dp-1=v0.64.0",
		Region:             "eu-west-1",
		DeploymentType:     "self-hosted",
		TrustGuardBaseURL:  "https://trustguard.eu.example.com",
		TrustGuardClientID: "tgc_eu",
	}
	if got != want {
		t.Fatalf("MarkHeartbeat = %+v, want %+v", got, want)
	}

	if err := client.SendHeartbeat(context.Background()); err != nil {
		t.Fatalf("SendHeartbeat: %v", err)
	}
	eventually(t, func() bool { return len(store.heartbeatsSnapshot()) == 2 }, "periodic heartbeat never recorded")
}

func TestClient_SendHeartbeatWithoutStreamIsNoOp(t *testing.T) {
	store := &recordingStore{}
	lis, _ := newBufServer(t, NewService(NewHub(discardLogger(), store), &fakeSource{}, discardLogger(), nil))
	client := dialClient(t, lis, "dp-1")
	client.SetHeartbeat(dataplane.Heartbeat{Version: "v1"})

	if err := client.SendHeartbeat(context.Background()); err != nil {
		t.Fatalf("SendHeartbeat with no stream: %v, want nil", err)
	}
	time.Sleep(50 * time.Millisecond)
	if got := store.heartbeatsSnapshot(); len(got) != 0 {
		t.Fatalf("MarkHeartbeat = %v, want none before the stream opens", got)
	}
}

func TestClient_WithoutHeartbeatSendsNone(t *testing.T) {
	store := &recordingStore{}
	hub := NewHub(discardLogger(), store)
	lis, _ := newBufServer(t, NewService(hub, &fakeSource{}, discardLogger(), nil))
	client := dialClient(t, lis, "dp-1")

	go func() { _, _ = client.Watch(context.Background()) }()

	eventually(t, func() bool { return hub.ConnectionCount() == 1 }, "stream never registered")
	if err := client.SendHeartbeat(context.Background()); err != nil {
		t.Fatalf("SendHeartbeat: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	if got := store.heartbeatsSnapshot(); len(got) != 0 {
		t.Fatalf("MarkHeartbeat = %v, want none from a client with no heartbeat set", got)
	}
}

func TestHub_RefreshPresenceTouchesHeldStreams(t *testing.T) {
	store := &recordingStore{}
	h := NewHub(discardLogger(), store)

	a := h.register(configsyncrevocation.Identity{Scope: "gw-a"}, "dp-1")
	b := h.register(configsyncrevocation.Identity{Scope: "gw-b"}, "dp-2")
	h.unregister(b)
	defer h.unregister(a)

	h.refreshPresence(context.Background())

	touched := store.touchedSnapshot()
	if len(touched) != 1 || !slices.Equal(touched[0], []string{"gw-a/dp-1"}) {
		t.Fatalf("TouchConnected = %v, want [[gw-a/dp-1]]", touched)
	}
}

func TestHub_RefreshPresenceSkipsWriteWithNoStreams(t *testing.T) {
	store := &recordingStore{}
	h := NewHub(discardLogger(), store)

	h.refreshPresence(context.Background())

	if touched := store.touchedSnapshot(); len(touched) != 0 {
		t.Fatalf("TouchConnected = %v, want no write without streams", touched)
	}
}

func TestHub_RunPresenceRefreshesUntilCancelled(t *testing.T) {
	store := &recordingStore{}
	h := NewHub(discardLogger(), store)
	conn := h.register(configsyncrevocation.Identity{Scope: "gw-a"}, "dp-1")
	defer h.unregister(conn)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		h.RunPresence(ctx, 10*time.Millisecond)
		close(done)
	}()

	eventually(t, func() bool { return len(store.touchedSnapshot()) >= 2 }, "presence never refreshed")
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("RunPresence did not return after cancel")
	}
}

func TestHub_RunPresenceWithoutStoreReturns(t *testing.T) {
	h := NewHub(discardLogger(), nil)
	done := make(chan struct{})
	go func() {
		h.RunPresence(context.Background(), time.Millisecond)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("RunPresence without a store must return at once")
	}
}

func TestHeartbeatFromProtoCapsFields(t *testing.T) {
	long := strings.Repeat("a", maxHeartbeatField-1) + "é"
	got := heartbeatFromProto(&snapshotpb.Heartbeat{
		Version:           long,
		Region:            "eu-west-1",
		TrustguardBaseUrl: "https://guard.example.com/" + strings.Repeat("p", maxHeartbeatURL),
	})
	if got.Version != strings.Repeat("a", maxHeartbeatField-1) {
		t.Fatalf("Version = %q (len %d), want the cut before the split rune", got.Version, len(got.Version))
	}
	if !utf8.ValidString(got.Version) {
		t.Fatal("Version is not valid UTF-8 after the cut")
	}
	if got.Region != "eu-west-1" {
		t.Fatalf("Region = %q, want it unchanged", got.Region)
	}
	if len(got.TrustGuardBaseURL) != maxHeartbeatURL {
		t.Fatalf("len(TrustGuardBaseURL) = %d, want %d", len(got.TrustGuardBaseURL), maxHeartbeatURL)
	}
}

func TestTruncateUTF8DropsInvalidBytes(t *testing.T) {
	if got := truncateUTF8("v1\xffx", 10); got != "v1x" {
		t.Fatalf("truncateUTF8 = %q, want v1x", got)
	}
}

func TestHeartbeatFromProtoDropsUnknownDeploymentType(t *testing.T) {
	if got := heartbeatFromProto(&snapshotpb.Heartbeat{DeploymentType: "hybrid"}); got.DeploymentType != "" {
		t.Fatalf("DeploymentType = %q, want an unknown value dropped", got.DeploymentType)
	}
	if got := heartbeatFromProto(&snapshotpb.Heartbeat{DeploymentType: dataplane.DeploymentSaaS}); got.DeploymentType != dataplane.DeploymentSaaS {
		t.Fatalf("DeploymentType = %q, want saas kept", got.DeploymentType)
	}
}

func TestClientAckStopsWaitingForTheSendSlotWhenCtxEnds(t *testing.T) {
	c := newClient(nil, "dp-1", discardLogger())
	if err := c.lockSend(context.Background()); err != nil {
		t.Fatalf("lockSend: %v", err)
	}
	defer c.unlockSend()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- c.Ack(ctx, "v1") }()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Ack = %v, want context.DeadlineExceeded", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Ack kept waiting for the send slot after its ctx ended")
	}
}

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
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"

	"github.com/NeuralTrust/TrustGate/pkg/domain/dataplane"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/secretstore"
	snapshotpb "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot/proto"
)

// SetHeartbeat makes the client report hb right after the Hello of every Sync
// stream it opens, and on each tick of RunHeartbeat.
func (c *Client) SetHeartbeat(hb dataplane.Heartbeat) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.heartbeat = &snapshotpb.Heartbeat{
		Version:            hb.Version,
		Region:             hb.Region,
		DeploymentType:     hb.DeploymentType,
		TrustguardBaseUrl:  hb.TrustGuardBaseURL,
		TrustguardClientId: hb.TrustGuardClientID,
	}
}

// SetSecretStoreReporter makes every heartbeat carry the secret stores fn
// returns at that moment.
func (c *Client) SetSecretStoreReporter(fn func() []secretstore.Status) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.secretStores = fn
}

// currentHeartbeat is the heartbeat to send now: the fixed fields, the
// secret references capability this build always has, and the secret stores
// as they are now. Nil before SetHeartbeat.
func (c *Client) currentHeartbeat() *snapshotpb.Heartbeat {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.currentHeartbeatLocked()
}

// currentHeartbeatLocked is currentHeartbeat for a caller that holds c.mu.
func (c *Client) currentHeartbeatLocked() *snapshotpb.Heartbeat {
	base, report := c.heartbeat, c.secretStores
	if base == nil {
		return nil
	}
	hb := proto.Clone(base).(*snapshotpb.Heartbeat)
	hb.AcceptsSecretRefs = true
	if report != nil {
		hb.SecretStores = secretStoresToProto(report())
	}
	return hb
}

// SendHeartbeat sends the heartbeat on the open Sync stream. With no stream
// open it does nothing: the worker opens one, and one follows its Hello.
func (c *Client) SendHeartbeat(ctx context.Context) error {
	c.mu.Lock()
	stream := c.stream
	c.mu.Unlock()
	hb := c.currentHeartbeat()
	if stream == nil || hb == nil {
		return nil
	}
	if err := c.lockSend(ctx); err != nil {
		return err
	}
	defer c.unlockSend()
	msg := &snapshotpb.ClientMessage{Msg: &snapshotpb.ClientMessage_Heartbeat{Heartbeat: hb}}
	result := make(chan error, 1)
	go func() { result <- stream.Send(msg) }()
	select {
	case <-ctx.Done():
		c.resetStream(stream)
		<-result
		return ctx.Err()
	case err := <-result:
		if err != nil {
			return fmt.Errorf("configsync: heartbeat send: %w", err)
		}
		return nil
	}
}

// RunHeartbeat sends the heartbeat every interval until ctx is done. A failed
// send is left to the worker, whose receive on the same stream fails too and
// reconnects.
func (c *Client) RunHeartbeat(ctx context.Context) {
	if c.heartbeatInterval <= 0 {
		return
	}
	ticker := time.NewTicker(c.heartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := c.SendHeartbeat(ctx); err != nil && ctx.Err() == nil {
				c.logger.DebugContext(ctx, "configsync: heartbeat not sent", slog.String("error", err.Error()))
			}
		}
	}
}

// Caps on what a data plane reports, so a misbehaving one cannot write
// arbitrarily large values to the store on every heartbeat.
const (
	maxHeartbeatField  = 256
	maxHeartbeatURL    = 2048
	maxSecretStores    = 50
	maxSecretStoreList = 50
)

func heartbeatFromProto(hb *snapshotpb.Heartbeat) dataplane.Heartbeat {
	return dataplane.Heartbeat{
		Version:            truncateUTF8(hb.GetVersion(), maxHeartbeatField),
		Region:             truncateUTF8(hb.GetRegion(), maxHeartbeatField),
		DeploymentType:     dataplane.KnownDeploymentType(hb.GetDeploymentType()),
		TrustGuardBaseURL:  truncateUTF8(hb.GetTrustguardBaseUrl(), maxHeartbeatURL),
		TrustGuardClientID: truncateUTF8(hb.GetTrustguardClientId(), maxHeartbeatField),
		AcceptsSecretRefs:  hb.GetAcceptsSecretRefs(),
		SecretStores:       secretStoresFromProto(hb.GetSecretStores()),
	}
}

func secretStoresToProto(in []secretstore.Status) []*snapshotpb.SecretStoreStatus {
	out := make([]*snapshotpb.SecretStoreStatus, 0, len(in))
	for _, s := range in {
		checked := ""
		if !s.CheckedAt.IsZero() {
			checked = s.CheckedAt.UTC().Format(time.RFC3339)
		}
		gateways := make([]string, 0, len(s.Gateways))
		for _, gw := range s.Gateways {
			gateways = append(gateways, gw.String())
		}
		out = append(out, &snapshotpb.SecretStoreStatus{
			Name: s.Name, Type: string(s.Type), AllowedPaths: s.AllowedPaths,
			State: string(s.State), ErrorClass: string(s.ErrorClass), CheckedAt: checked, Gateways: gateways,
		})
	}
	return out
}

// secretStoresFromProto keeps what a data plane reports within bounds:
// at most maxSecretStores stores, lists of at most maxSecretStoreList
// entries, capped fields, and only gateway ids that parse.
func secretStoresFromProto(in []*snapshotpb.SecretStoreStatus) []secretstore.Status {
	if len(in) == 0 {
		return nil
	}
	if len(in) > maxSecretStores {
		in = in[:maxSecretStores]
	}
	out := make([]secretstore.Status, 0, len(in))
	for _, s := range in {
		st := secretstore.Status{
			Name:       truncateUTF8(s.GetName(), maxHeartbeatField),
			Type:       secretstore.Type(truncateUTF8(s.GetType(), maxHeartbeatField)),
			State:      secretstore.State(truncateUTF8(s.GetState(), maxHeartbeatField)),
			ErrorClass: secretstore.Class(truncateUTF8(s.GetErrorClass(), maxHeartbeatField)),
		}
		for i, p := range s.GetAllowedPaths() {
			if i == maxSecretStoreList {
				break
			}
			st.AllowedPaths = append(st.AllowedPaths, truncateUTF8(p, maxHeartbeatField))
		}
		for i, raw := range s.GetGateways() {
			if i == maxSecretStoreList {
				break
			}
			if gw, err := ids.Parse[ids.GatewayKind](raw); err == nil {
				st.Gateways = append(st.Gateways, gw)
			}
		}
		if t, err := time.Parse(time.RFC3339, s.GetCheckedAt()); err == nil {
			st.CheckedAt = t
		}
		out = append(out, st)
	}
	return out
}

// truncateUTF8 cuts s to at most limit bytes and drops invalid UTF-8, which
// Postgres would otherwise reject along with the whole write.
func truncateUTF8(s string, limit int) string {
	if len(s) > limit {
		cut := limit
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut]
	}
	return strings.ToValidUTF8(s, "")
}

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

	"github.com/NeuralTrust/TrustGate/pkg/domain/dataplane"
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

// SendHeartbeat sends the heartbeat on the open Sync stream. With no stream
// open it does nothing: the worker opens one, and one follows its Hello.
func (c *Client) SendHeartbeat(ctx context.Context) error {
	c.mu.Lock()
	stream, hb := c.stream, c.heartbeat
	c.mu.Unlock()
	if stream == nil || hb == nil {
		return nil
	}
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
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
	maxHeartbeatField = 256
	maxHeartbeatURL   = 2048
)

func heartbeatFromProto(hb *snapshotpb.Heartbeat) dataplane.Heartbeat {
	return dataplane.Heartbeat{
		Version:            truncateUTF8(hb.GetVersion(), maxHeartbeatField),
		Region:             truncateUTF8(hb.GetRegion(), maxHeartbeatField),
		DeploymentType:     truncateUTF8(hb.GetDeploymentType(), maxHeartbeatField),
		TrustGuardBaseURL:  truncateUTF8(hb.GetTrustguardBaseUrl(), maxHeartbeatURL),
		TrustGuardClientID: truncateUTF8(hb.GetTrustguardClientId(), maxHeartbeatField),
	}
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

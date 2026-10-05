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
	"encoding/json"
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	snapshotpb "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot/proto"
	"google.golang.org/grpc"
)

// PinnedToolsClient reports pending pinned tools from a DB-less data plane to
// the control plane over the connection it already holds. It satisfies the MCP
// layer's PendingToolRecorder structurally; that layer owns timeouts, retries,
// dedupe and metrics, so this only translates and splits batches.
type PinnedToolsClient struct {
	cli snapshotpb.PinnedToolsClient
}

func NewPinnedToolsClient(conn *grpc.ClientConn) *PinnedToolsClient {
	return &PinnedToolsClient{cli: snapshotpb.NewPinnedToolsClient(conn)}
}

// Record sends the candidates in batches the server accepts. The fingerprint is
// not sent: the server recomputes it from name, description and input schema.
func (c *PinnedToolsClient) Record(
	ctx context.Context,
	gatewayID ids.GatewayID,
	registryID ids.RegistryID,
	tools []registrydomain.ToolCandidate,
) error {
	wire := make([]*snapshotpb.PendingTool, 0, len(tools))
	for _, t := range tools {
		pt, err := pendingToolFromCandidate(t)
		if err != nil {
			return fmt.Errorf("pinned tools: encode %q: %w", t.Name, err)
		}
		wire = append(wire, pt)
	}
	for start := 0; start < len(wire); start += MaxPendingToolsPerCall {
		end := min(start+MaxPendingToolsPerCall, len(wire))
		if _, err := c.cli.RecordPending(ctx, &snapshotpb.RecordPendingToolsRequest{
			GatewayId:  gatewayID.String(),
			RegistryId: registryID.String(),
			Tools:      wire[start:end],
		}); err != nil {
			return fmt.Errorf("pinned tools: record pending: %w", err)
		}
	}
	return nil
}

// pendingToolFromCandidate unpacks the canonical definition the candidate was
// fingerprinted from. Canonicalising it again on the server yields the same
// bytes, so the two fingerprints agree.
func pendingToolFromCandidate(t registrydomain.ToolCandidate) (*snapshotpb.PendingTool, error) {
	var def struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		InputSchema json.RawMessage `json:"inputSchema"`
	}
	if err := json.Unmarshal(t.Definition, &def); err != nil {
		return nil, err
	}
	return &snapshotpb.PendingTool{
		Name:        def.Name,
		Description: def.Description,
		InputSchema: def.InputSchema,
	}, nil
}

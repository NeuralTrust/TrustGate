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
	"errors"
	"log/slog"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	snapshotpb "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot/proto"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	// MaxPendingToolsPerCall bounds one RecordPending call; the data plane's
	// recorder splits larger batches.
	MaxPendingToolsPerCall = 100
	// MaxPendingToolBytes bounds one tool's name + description + input schema.
	MaxPendingToolBytes = 64 << 10
	// MaxPendingToolNameBytes bounds a tool name.
	MaxPendingToolNameBytes = 256

	pendingToolsWho = "pinned tools"
)

// PendingRegistryFinder is the slice of the registry repository the check needs.
type PendingRegistryFinder interface {
	FindByID(ctx context.Context, id ids.RegistryID) (*registrydomain.Registry, error)
}

// PendingToolStore is the slice of the pinned tool repository the handler may
// use: it can only insert pending rows, so this channel has no way to approve or
// reject a tool even by mistake.
type PendingToolStore interface {
	UpsertPending(ctx context.Context, gatewayID ids.GatewayID, registryID ids.RegistryID, tools []registrydomain.ToolCandidate) (inserted, dropped int, err error)
}

// PinnedToolsService is the control-plane end of the PinnedTools channel. It
// treats the caller as untrusted: the gateway is authorised against the caller's
// config-sync scope exactly like every other RPC here, the registry must be the
// gateway's and pinned, fingerprints are recomputed from the definitions, sizes
// are bounded, and only pending rows are ever written.
type PinnedToolsService struct {
	snapshotpb.UnimplementedPinnedToolsServer
	registries PendingRegistryFinder
	tools      PendingToolStore
	gateways   GatewayResolver
	logger     *slog.Logger
	capped     metric.Int64Counter
}

func NewPinnedToolsService(
	registries PendingRegistryFinder,
	tools PendingToolStore,
	gateways GatewayResolver,
	logger *slog.Logger,
) *PinnedToolsService {
	if logger == nil {
		logger = slog.Default()
	}
	capped, err := otel.GetMeterProvider().Meter("trustgate/configsync").Int64Counter(
		"trustgate.pinned_tools.capped",
		metric.WithDescription("new pending tool definitions dropped because a registry or tool name hit its pending cap"))
	if err != nil {
		capped = noop.Int64Counter{}
	}
	return &PinnedToolsService{registries: registries, tools: tools, gateways: gateways, logger: logger, capped: capped}
}

func (s *PinnedToolsService) RecordPending(
	ctx context.Context,
	req *snapshotpb.RecordPendingToolsRequest,
) (*snapshotpb.RecordPendingToolsResponse, error) {
	gatewayID, err := parseGatewayID(req.GetGatewayId(), "record pending")
	if err != nil {
		return nil, err
	}
	if err := authorizeGatewayScope(ctx, s.gateways, s.logger, pendingToolsWho, "record pending", gatewayID); err != nil {
		return nil, err
	}
	registryID, err := ids.Parse[ids.RegistryKind](req.GetRegistryId())
	if err != nil || registryID.IsNil() {
		return nil, status.Errorf(codes.InvalidArgument, "%s: record pending: a valid registry id is required", pendingToolsWho)
	}
	candidates, skipped, err := candidatesFromRequest(req.GetTools())
	if err != nil {
		return nil, err
	}
	if skipped > 0 {
		s.logger.Warn("pinned tools: skipped invalid tool definitions",
			slog.String("component", component),
			slog.String("registry_id", registryID.String()),
			slog.Int("skipped", skipped))
	}
	// Every response below says what was skipped; accepted is what survived.
	result := func(recorded, dropped int) *snapshotpb.RecordPendingToolsResponse {
		return &snapshotpb.RecordPendingToolsResponse{
			Recorded: int32(recorded), Dropped: int32(dropped), Accepted: int32(len(candidates)), Skipped: int32(skipped),
		}
	}
	if len(candidates) == 0 {
		return result(0, 0), nil
	}

	reg, err := s.registries.FindByID(ctx, registryID)
	switch {
	case err != nil && isNotFound(err):
		return result(0, 0), nil
	case err != nil:
		return nil, status.Errorf(codes.Internal, "%s: record pending: load registry: %v", pendingToolsWho, err)
	}
	// Another gateway's registry, or one that is not pinned, is ignored without
	// saying which: the caller learns nothing about registries it does not own.
	if reg == nil || reg.GatewayID != gatewayID || !reg.ToolPolicy.IsPinned() {
		return result(0, 0), nil
	}
	n, dropped, err := s.tools.UpsertPending(ctx, gatewayID, registryID, candidates)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%s: record pending: %v", pendingToolsWho, err)
	}
	if dropped > 0 {
		s.capped.Add(ctx, int64(dropped))
		s.logger.Warn("pinned tools: pending cap reached; new definitions were not stored",
			slog.String("component", component),
			slog.String("gateway_id", gatewayID.String()),
			slog.String("registry_id", registryID.String()),
			slog.Int("dropped", dropped))
	}
	return result(n, dropped), nil
}

// candidatesFromRequest builds each candidate through NewToolCandidate, so the
// fingerprint is always the server's own computation. A call above the per-call
// limit is refused as a whole; a single invalid tool (empty or oversized name,
// oversized definition, NUL) is skipped and counted so one hostile or odd tool
// cannot keep the others from being recorded.
func candidatesFromRequest(tools []*snapshotpb.PendingTool) (valid []registrydomain.ToolCandidate, skipped int, err error) {
	if len(tools) > MaxPendingToolsPerCall {
		return nil, 0, status.Errorf(codes.InvalidArgument,
			"%s: record pending: %d tools exceed the limit of %d per call", pendingToolsWho, len(tools), MaxPendingToolsPerCall)
	}
	valid = make([]registrydomain.ToolCandidate, 0, len(tools))
	for _, t := range tools {
		name := t.GetName()
		if name == "" || len(name) > MaxPendingToolNameBytes ||
			len(name)+len(t.GetDescription())+len(t.GetInputSchema()) > MaxPendingToolBytes {
			skipped++
			continue
		}
		cand, err := registrydomain.NewToolCandidate(name, t.GetDescription(), json.RawMessage(t.GetInputSchema()))
		if err != nil {
			skipped++
			continue
		}
		valid = append(valid, cand)
	}
	return valid, skipped, nil
}

func isNotFound(err error) bool {
	return errors.Is(err, commonerrors.ErrNotFound)
}

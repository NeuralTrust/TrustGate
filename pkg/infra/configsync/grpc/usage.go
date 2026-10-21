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
	"log/slog"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	usagedomain "github.com/NeuralTrust/TrustGate/pkg/domain/usage"
	snapshotpb "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot/proto"
)

// UsageSource is the control plane's view of tenant usage states.
type UsageSource interface {
	SnapshotAll() usagedomain.Snapshot
	SnapshotTenant(tenantID string) usagedomain.Snapshot
	Subscribe() (<-chan struct{}, func())
	// Ready reports whether the source holds a list worth sending. Until it
	// does nothing is sent: a data plane reads any list as complete.
	Ready() bool
}

// ServiceOption configures optional parts of the ConfigSync service.
type ServiceOption func(*Service)

// WithUsage makes Sync push the exhausted tenants to every data plane: on
// connect and after each change. gateways maps a gateway scope to its tenant.
func WithUsage(source UsageSource, gateways GatewayResolver) ServiceOption {
	return func(s *Service) {
		s.usage = source
		s.usageGateways = gateways
	}
}

// usageSnapshotFor builds the usage message one connection may receive. Only
// the unscoped in-cluster data planes get every tenant. A data plane scoped to
// a gateway gets that gateway's tenant, and a scope that is not a gateway id
// names its tenant directly; it never gets another tenant's state. When a
// gateway scope cannot be resolved (unknown, deleted, or the lookup failed)
// nothing is sent, so the data plane keeps what it has instead of reading an
// empty list as "nobody is exhausted".
func (s *Service) usageSnapshotFor(ctx context.Context, scope string) (*snapshotpb.ServerMessage, bool) {
	if !s.usage.Ready() {
		return nil, false
	}
	if scope == "" {
		return usageMessage(s.usage.SnapshotAll()), true
	}
	tenantID, ok := s.usageTenantFor(ctx, scope)
	if !ok {
		return nil, false
	}
	return usageMessage(s.usage.SnapshotTenant(tenantID)), true
}

func (s *Service) usageTenantFor(ctx context.Context, scope string) (string, bool) {
	gatewayID, err := ids.Parse[ids.GatewayKind](scope)
	if err != nil {
		return scope, true
	}
	if s.usageGateways == nil {
		return "", false
	}
	gw, err := s.usageGateways.FindByID(ctx, gatewayID)
	if err != nil {
		s.logger.DebugContext(ctx, "configsync: resolve usage scope", slog.String("scope", scope), slog.Any("error", err))
		return "", false
	}
	return gw.TenantID(), true
}

func usageMessage(snapshot usagedomain.Snapshot) *snapshotpb.ServerMessage {
	msg := &snapshotpb.UsageSnapshot{AsOfVersion: snapshot.AsOfVersion}
	for _, state := range snapshot.Exhausted {
		msg.Exhausted = append(msg.Exhausted, &snapshotpb.TenantUsage{
			TenantId: state.TenantID,
			Reason:   usageReasonToProto(state.Reason),
			Version:  state.Version,
		})
	}
	return &snapshotpb.ServerMessage{Msg: &snapshotpb.ServerMessage_Usage{Usage: msg}}
}

func usageSnapshotFromProto(msg *snapshotpb.UsageSnapshot) usagedomain.Snapshot {
	out := usagedomain.Snapshot{AsOfVersion: msg.GetAsOfVersion()}
	for _, entry := range msg.GetExhausted() {
		version := entry.GetVersion()
		if version <= 0 {
			version = msg.GetAsOfVersion()
		}
		state, err := usagedomain.NewTenantState(entry.GetTenantId(), usagedomain.StatusExhausted, usageReasonFromProto(entry.GetReason()), version)
		if err != nil {
			continue
		}
		out.Exhausted = append(out.Exhausted, state)
	}
	return out
}

func usageReasonFromProto(reason snapshotpb.UsageReason) usagedomain.Reason {
	if reason == snapshotpb.UsageReason_USAGE_REASON_FREE_LIMIT_REACHED {
		return usagedomain.ReasonFreeLimitReached
	}
	return usagedomain.ReasonWalletEmpty
}

func usageReasonToProto(reason usagedomain.Reason) snapshotpb.UsageReason {
	switch reason {
	case usagedomain.ReasonFreeLimitReached:
		return snapshotpb.UsageReason_USAGE_REASON_FREE_LIMIT_REACHED
	case usagedomain.ReasonWalletEmpty:
		return snapshotpb.UsageReason_USAGE_REASON_WALLET_EMPTY
	default:
		return snapshotpb.UsageReason_USAGE_REASON_UNSPECIFIED
	}
}

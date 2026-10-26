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
	Cursor() uint64
	ChangesSince(cursor uint64) ([]usagedomain.TenantState, uint64)
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

// maxUsageChangesPerMessage bounds a UsageChanges message, so a burst such as
// every tenant being unblocked at once goes out in several messages.
const maxUsageChangesPerMessage = 1000

// usageStream tracks what one Sync stream has been sent. Only the unscoped
// in-cluster data planes get every tenant. A data plane scoped to a gateway
// gets that gateway's tenant, and a scope that is not a gateway id names its
// tenant directly; it never gets another tenant's state.
type usageStream struct {
	svc     *Service
	scope   string
	changes bool

	tenantID string
	resolved bool
	// listed is set once a data plane that takes changes has been sent a
	// complete list; from then on it only gets what changed after cursor.
	listed bool
	cursor uint64
}

func (s *Service) newUsageStream(scope string, acceptsChanges bool) *usageStream {
	return &usageStream{svc: s, scope: scope, changes: acceptsChanges, resolved: scope == ""}
}

// next returns the usage messages the stream is owed now, and false when it
// owes one it cannot send yet: the source is not ready or a gateway scope did
// not resolve (unknown, deleted, or the lookup failed). The data plane then
// keeps what it has instead of reading an empty list as "nobody is
// exhausted". A data plane that does not take changes gets the full list
// every time. One that does gets full lists until one is complete, because a
// list with no as_of version unblocks nobody and only the next complete list
// can, and then the tenants that changed since.
func (u *usageStream) next(ctx context.Context) ([]*snapshotpb.ServerMessage, bool) {
	if !u.svc.usage.Ready() || !u.resolve(ctx) {
		return nil, false
	}
	if u.listed {
		return u.changedSince(), true
	}
	cursor := u.svc.usage.Cursor()
	snapshot := u.svc.usage.SnapshotAll()
	if u.scope != "" {
		snapshot = u.svc.usage.SnapshotTenant(u.tenantID)
	}
	u.cursor = cursor
	u.listed = u.changes && snapshot.AsOfVersion > 0
	return []*snapshotpb.ServerMessage{usageMessage(snapshot)}, true
}

func (u *usageStream) changedSince() []*snapshotpb.ServerMessage {
	states, cursor := u.svc.usage.ChangesSince(u.cursor)
	u.cursor = cursor
	if u.scope != "" {
		var own []usagedomain.TenantState
		for _, state := range states {
			if u.tenantID != "" && state.TenantID == u.tenantID {
				own = append(own, state)
			}
		}
		states = own
	}
	var out []*snapshotpb.ServerMessage
	for start := 0; start < len(states); start += maxUsageChangesPerMessage {
		out = append(out, usageChangesMessage(states[start:min(start+maxUsageChangesPerMessage, len(states))]))
	}
	return out
}

func (u *usageStream) resolve(ctx context.Context) bool {
	if u.resolved {
		return true
	}
	gatewayID, err := ids.Parse[ids.GatewayKind](u.scope)
	if err != nil {
		u.tenantID, u.resolved = u.scope, true
		return true
	}
	if u.svc.usageGateways == nil {
		return false
	}
	gw, err := u.svc.usageGateways.FindByID(ctx, gatewayID)
	if err != nil {
		u.svc.logger.DebugContext(ctx, "configsync: resolve usage scope", slog.String("scope", u.scope), slog.Any("error", err))
		return false
	}
	u.tenantID, u.resolved = gw.TenantID(), true
	return true
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

func usageChangesMessage(states []usagedomain.TenantState) *snapshotpb.ServerMessage {
	msg := &snapshotpb.UsageChanges{States: make([]*snapshotpb.TenantUsageState, 0, len(states))}
	for _, state := range states {
		status := snapshotpb.UsageStatus_USAGE_STATUS_HEALTHY
		if state.Exhausted() {
			status = snapshotpb.UsageStatus_USAGE_STATUS_EXHAUSTED
		}
		msg.States = append(msg.States, &snapshotpb.TenantUsageState{
			TenantId: state.TenantID,
			Status:   status,
			Reason:   usageReasonToProto(state.Reason),
			Version:  state.Version,
		})
	}
	return &snapshotpb.ServerMessage{Msg: &snapshotpb.ServerMessage_UsageChanges{UsageChanges: msg}}
}

// usageChangesFromProto drops the entries it cannot apply: unlike a list, a
// change has no as_of version to stand in for a missing one, and a state
// whose status is unknown could unblock a tenant by mistake.
func usageChangesFromProto(msg *snapshotpb.UsageChanges) []usagedomain.TenantState {
	out := make([]usagedomain.TenantState, 0, len(msg.GetStates()))
	for _, entry := range msg.GetStates() {
		var status usagedomain.Status
		switch entry.GetStatus() {
		case snapshotpb.UsageStatus_USAGE_STATUS_HEALTHY:
			status = usagedomain.StatusHealthy
		case snapshotpb.UsageStatus_USAGE_STATUS_EXHAUSTED:
			status = usagedomain.StatusExhausted
		default:
			continue
		}
		state, err := usagedomain.NewTenantState(entry.GetTenantId(), status, usageReasonFromProto(entry.GetReason()), entry.GetVersion())
		if err != nil {
			continue
		}
		out = append(out, state)
	}
	return out
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

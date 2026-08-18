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

package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
)

// MethodSubscriptionsListen is the modern-only method that opens a bounded
// notification lease.
const MethodSubscriptionsListen = "subscriptions/listen"

// MetaKeySubscriptionID is the _meta key every frame of a lease carries, equal to
// the listen call's JSON-RPC id.
const MetaKeySubscriptionID = "io.modelcontextprotocol/subscriptionId"

const surfaceConfigDigestBytes = 16

// NotificationKind is a notification type a client may ask to be streamed.
type NotificationKind string

const (
	NotificationToolsListChanged     NotificationKind = "toolsListChanged"
	NotificationPromptsListChanged   NotificationKind = "promptsListChanged"
	NotificationResourcesListChanged NotificationKind = "resourcesListChanged"
)

// notificationMethods maps every bindable kind to the JSON-RPC notification
// method it is delivered as. Membership of this map is the whole allow-list:
// a kind absent from it can never be bound.
var notificationMethods = map[NotificationKind]string{
	NotificationToolsListChanged:     "notifications/tools/list_changed",
	NotificationPromptsListChanged:   "notifications/prompts/list_changed",
	NotificationResourcesListChanged: "notifications/resources/list_changed",
}

// notificationOrder is the deterministic order honoured kinds are reported in.
var notificationOrder = []NotificationKind{
	NotificationToolsListChanged,
	NotificationPromptsListChanged,
	NotificationResourcesListChanged,
}

// BoundNotificationKind resolves a client-supplied string to a known kind. The
// second result is false for anything TrustGate cannot stream, so an unknown
// notification type is refused rather than silently ignored.
func BoundNotificationKind(raw string) (NotificationKind, bool) {
	kind := NotificationKind(raw)
	if _, ok := notificationMethods[kind]; !ok {
		return "", false
	}
	return kind, true
}

// Method is the JSON-RPC notification method this kind is delivered as.
func (k NotificationKind) Method() string {
	return notificationMethods[k]
}

// HonouredSet is the set of notification kinds a lease actually streams, which
// is never larger than what the client requested.
type HonouredSet struct {
	kinds map[NotificationKind]struct{}
}

// NewHonouredSet builds the set of the given kinds, discarding duplicates.
func NewHonouredSet(kinds ...NotificationKind) HonouredSet {
	set := HonouredSet{kinds: make(map[NotificationKind]struct{}, len(kinds))}
	for _, kind := range kinds {
		if _, ok := notificationMethods[kind]; !ok {
			continue
		}
		set.kinds[kind] = struct{}{}
	}
	return set
}

// Has reports whether the kind is streamed by this lease.
func (s HonouredSet) Has(kind NotificationKind) bool {
	_, ok := s.kinds[kind]
	return ok
}

// Empty reports whether the set honours nothing.
func (s HonouredSet) Empty() bool {
	return len(s.kinds) == 0
}

// Kinds is the honoured kinds in a fixed order (tools, prompts, resources) so
// the value echoed to a client never depends on map iteration.
func (s HonouredSet) Kinds() []NotificationKind {
	out := make([]NotificationKind, 0, len(s.kinds))
	for _, kind := range notificationOrder {
		if s.Has(kind) {
			out = append(out, kind)
		}
	}
	return out
}

// Intersect narrows the set to the kinds also present in other.
func (s HonouredSet) Intersect(other HonouredSet) HonouredSet {
	out := HonouredSet{kinds: make(map[NotificationKind]struct{}, len(s.kinds))}
	for kind := range s.kinds {
		if other.Has(kind) {
			out.kinds[kind] = struct{}{}
		}
	}
	return out
}

// IsolationKey identifies the authorization context a lease was opened under.
// Two leases sharing a key see the same surface; any difference — gateway,
// consumer, principal or role scope — makes them separate streams, so a
// notification can never cross an authorization boundary.
type IsolationKey struct {
	GatewayID  string
	ConsumerID string
	Principal  string
	RoleScope  string
}

// SubscriptionIdentity is the complete independently authorized northbound binding identity.
type SubscriptionIdentity struct {
	GatewayID            string
	ConsumerID           string
	PrincipalFingerprint string
	AuthID               string
	RegistryID           string
	RoleScopeFingerprint string
	Path                 string
}

// String returns a safe label without exposing subscriber identity.
func (SubscriptionIdentity) String() string {
	return "mcp-subscription-binding"
}

// SubscriptionRequest binds one role-scoped registry target to requested kinds.
type SubscriptionRequest struct {
	Identity  SubscriptionIdentity
	Target    Target
	Requested HonouredSet
}

// SubscriptionHandle owns one bounded northbound event queue and terminal state.
type SubscriptionHandle interface {
	Events() <-chan SubscriptionEvent
	Done() <-chan struct{}
	Err() error
	Authorize(ctx context.Context, event SubscriptionEvent) error
	Close()
}

// SubscriptionSource atomically attaches northbound bindings and owns outbound lifecycle.
type SubscriptionSource interface {
	Attach(ctx context.Context, requests []SubscriptionRequest) (SubscriptionHandle, HonouredSet, error)
	Close(ctx context.Context) error
}

// NewIsolationKey derives the key for the acting request. The principal is the
// full fingerprint, not the truncation used for cache keys, so two subjects
// cannot collide into one stream identity.
func NewIsolationKey(ctx context.Context, gatewayID string, rc *appconsumer.RoutableConsumer) IsolationKey {
	principal := principalFingerprint(ctx)
	if principal == "" {
		if authID, ok := appconsumer.AuthIDFromContext(ctx); ok {
			principal = "auth:" + authID.String()
		}
	}
	key := IsolationKey{
		GatewayID: gatewayID,
		Principal: principal,
		RoleScope: SurfaceConfigFingerprint(rc),
	}
	if rc != nil && rc.Consumer != nil {
		key.ConsumerID = rc.Consumer.ID.String()
	}
	return key
}

// SurfaceConfigFingerprint is the digest of the configuration that decides a
// consumer's MCP surface: attached MCP registries with their update timestamps,
// and the resolved toolkit. A change to either must invalidate a lease, so the
// digest is deliberately conservative — an edit unrelated to the streamed kinds
// still terminates the stream (RUN-1104 locked decision 2).
func SurfaceConfigFingerprint(rc *appconsumer.RoutableConsumer) string {
	if rc == nil || rc.Consumer == nil {
		return "0"
	}
	parts := make([]string, 0, len(rc.Registries))
	for _, reg := range rc.Registries {
		if reg == nil || !reg.IsMCP() {
			continue
		}
		parts = append(parts, reg.ID.String()+"@"+reg.UpdatedAt.UTC().Format(time.RFC3339Nano))
	}
	toolkit := rc.Consumer.Toolkit()
	entries := make([]string, 0, len(toolkit)+1)
	if toolkit == nil {
		entries = append(entries, "tk-state:nil")
	} else {
		entries = append(entries, "tk-state:configured")
	}
	for _, e := range toolkit {
		entries = append(entries, "tk:"+e.RegistryID.String()+"/"+e.Tool+"/"+e.Prompt+"/"+e.Resource+"/"+e.ExposeAs)
	}
	sort.Strings(parts)
	sort.Strings(entries)
	sum := sha256.Sum256([]byte(strings.Join(append(parts, entries...), "|")))
	return hex.EncodeToString(sum[:surfaceConfigDigestBytes])
}

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
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"sync"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appstore "github.com/NeuralTrust/TrustGate/pkg/app/store"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
	"golang.org/x/sync/singleflight"
)

const (
	surfaceWatchTTL        = 5 * time.Second
	maxSurfaceWatchEntries = 1024
)

type CredentialLister interface {
	ListByPrincipal(ctx context.Context, gatewayID ids.GatewayID, principalSub string) ([]*vaultdomain.Credential, error)
}

type InstallationLister interface {
	ListByPrincipal(ctx context.Context, gatewayID ids.GatewayID, principalSub string) ([]*installationdomain.Installation, error)
}

type SurfaceWatcher interface {
	ConnectedEmail(ctx context.Context, gatewayID ids.GatewayID, principalSub string) string
	Connections(ctx context.Context, rc *appconsumer.RoutableConsumer, principal *identity.Principal, all bool) []string
	Installations(ctx context.Context, rc *appconsumer.RoutableConsumer, principal *identity.Principal) []string
	WatchSnapshot(ctx context.Context, rc *appconsumer.RoutableConsumer, principal *identity.Principal) string
}

type surfaceWatcher struct {
	credentials   CredentialLister
	installations InstallationLister
	// scoper is the Store scoper (optional): the same scoping tools/list applies,
	// so the snapshot also moves when an admin revokes a grant or tightens the
	// caller's access level — the install rows stay, the surface shrinks.
	scoper appstore.Scoper
	mu     sync.RWMutex
	cache  map[string]*surfaceWatchEntry
	lru    *list.List
	flight singleflight.Group
}

type surfaceWatchEntry struct {
	key       string
	value     string
	expiresAt time.Time
	element   *list.Element
}

// SurfaceWatcherOption tunes NewSurfaceWatcher.
type SurfaceWatcherOption func(*surfaceWatcher)

// WithSurfaceScoper makes the watch snapshot include the registries the Store
// scoper exposes to the caller right now. Without it a revoked server would stay
// in the client's cached tool list (its calls failing) until it reconnected:
// connections and installations are unchanged by a revocation, only the grant is.
func WithSurfaceScoper(scoper appstore.Scoper) SurfaceWatcherOption {
	return func(w *surfaceWatcher) { w.scoper = scoper }
}

func NewSurfaceWatcher(credentials CredentialLister, installations InstallationLister, opts ...SurfaceWatcherOption) SurfaceWatcher {
	w := &surfaceWatcher{
		credentials:   credentials,
		installations: installations,
		cache:         make(map[string]*surfaceWatchEntry),
		lru:           list.New(),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(w)
		}
	}
	return w
}

func (w *surfaceWatcher) WatchSnapshot(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	principal *identity.Principal,
) string {
	if !validSurfaceInput(rc, principal) {
		return ""
	}
	key := rc.Consumer.GatewayID.String() + "|" + principal.Subject
	if value, ok := w.cachedSnapshot(key); ok {
		return joinWatchSnapshot(value, consumerBindings(rc))
	}
	result := w.flight.DoChan(key, func() (any, error) {
		if value, ok := w.cachedSnapshot(key); ok {
			return value, nil
		}
		loadCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), surfaceWatchTTL)
		defer cancel()
		parts, err := w.loadConnections(loadCtx, rc, principal, true)
		if err != nil {
			return "", err
		}
		installations, err := w.loadInstallations(loadCtx, rc, principal)
		if err != nil {
			return "", err
		}
		parts = append(parts, installations...)
		surface, err := w.loadSurface(loadCtx, rc, principal)
		if err != nil {
			return "", err
		}
		parts = append(parts, surface...)
		value := strings.Join(parts, "|")
		w.storeSnapshot(key, value, time.Now())
		return value, nil
	})
	select {
	case <-ctx.Done():
		return ""
	case completed := <-result:
		if completed.Err != nil {
			return ""
		}
		dynamic, _ := completed.Val.(string)
		return joinWatchSnapshot(dynamic, consumerBindings(rc))
	}
}

func (w *surfaceWatcher) cachedSnapshot(key string) (string, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	entry, ok := w.cache[key]
	if !ok {
		return "", false
	}
	if !time.Now().Before(entry.expiresAt) {
		w.removeSnapshot(entry)
		return "", false
	}
	w.lru.MoveToFront(entry.element)
	return entry.value, true
}

func (w *surfaceWatcher) storeSnapshot(key, value string, now time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if existing, ok := w.cache[key]; ok {
		existing.value = value
		existing.expiresAt = now.Add(surfaceWatchTTL)
		w.lru.MoveToFront(existing.element)
		return
	}
	for cacheKey, entry := range w.cache {
		if !now.Before(entry.expiresAt) {
			delete(w.cache, cacheKey)
			w.lru.Remove(entry.element)
		}
	}
	for len(w.cache) >= maxSurfaceWatchEntries {
		oldest := w.lru.Back().Value.(*surfaceWatchEntry)
		w.removeSnapshot(oldest)
	}
	entry := &surfaceWatchEntry{key: key, value: value, expiresAt: now.Add(surfaceWatchTTL)}
	entry.element = w.lru.PushFront(entry)
	w.cache[key] = entry
}

func (w *surfaceWatcher) removeSnapshot(entry *surfaceWatchEntry) {
	delete(w.cache, entry.key)
	w.lru.Remove(entry.element)
}

func joinWatchSnapshot(dynamic string, bindings []string) string {
	if len(bindings) == 0 {
		return dynamic
	}
	extra := strings.Join(bindings, "|")
	if dynamic == "" {
		return extra
	}
	return dynamic + "|" + extra
}

// consumerBindings fingerprints the servers an admin bound to this consumer.
// Vault credentials and Store installs do not move when a registry is
// attached or detached, so without these parts the SSE watch stays quiet and
// the client keeps the tool list from handshake.
func consumerBindings(rc *appconsumer.RoutableConsumer) []string {
	if rc == nil || rc.Consumer == nil {
		return nil
	}
	parts := make([]string, 0, len(rc.Registries))
	for _, registry := range rc.Registries {
		if registry != nil && registry.IsMCP() {
			parts = append(parts, "rg:"+registry.ID.String()+"@"+registry.UpdatedAt.UTC().Format(time.RFC3339Nano))
		}
	}
	for _, entry := range rc.Consumer.Toolkit() {
		parts = append(parts, "tk:"+entry.RegistryID.String()+"/"+entry.Tool+"/"+entry.Prompt+"/"+entry.Resource+"/"+entry.ExposeAs)
	}
	sort.Strings(parts)
	return parts
}

func SurfaceFingerprint(rc *appconsumer.RoutableConsumer, dynamic []string) string {
	if rc == nil || rc.Consumer == nil {
		return "0"
	}
	parts := make([]string, 0, len(rc.Registries))
	for _, registry := range rc.Registries {
		if registry != nil && registry.IsMCP() {
			parts = append(parts, registry.ID.String()+"@"+registry.UpdatedAt.UTC().Format(time.RFC3339Nano))
		}
	}
	for _, entry := range rc.Consumer.Toolkit() {
		parts = append(parts, "tk:"+entry.RegistryID.String()+"/"+entry.Tool+"/"+entry.Prompt+"/"+entry.Resource+"/"+entry.ExposeAs)
	}
	parts = append(parts, dynamic...)
	sort.Strings(parts)
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:6])
}

func (w *surfaceWatcher) ConnectedEmail(ctx context.Context, gatewayID ids.GatewayID, principalSub string) string {
	if w.credentials == nil {
		return ""
	}
	return ConnectedAccountEmail(ctx, w.credentials, gatewayID, principalSub)
}

func (w *surfaceWatcher) Connections(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	principal *identity.Principal,
	all bool,
) []string {
	parts, _ := w.loadConnections(ctx, rc, principal, all)
	return parts
}

func (w *surfaceWatcher) loadConnections(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	principal *identity.Principal,
	all bool,
) ([]string, error) {
	if w.credentials == nil || !validSurfaceInput(rc, principal) {
		return nil, nil
	}
	allowed := forwardedSurfaceProviders(rc)
	if !all && len(allowed) == 0 {
		return nil, nil
	}
	credentials, err := w.credentials.ListByPrincipal(ctx, rc.Consumer.GatewayID, principal.Subject)
	if err != nil {
		return nil, err
	}
	parts := make([]string, 0, len(credentials))
	for _, credential := range credentials {
		if credential == nil {
			continue
		}
		if !all {
			if _, ok := allowed[credential.Provider]; !ok {
				continue
			}
		}
		parts = append(parts, "cx:"+credential.Provider+"@"+credential.UpdatedAt.UTC().Format(time.RFC3339Nano))
	}
	sort.Strings(parts)
	return parts, nil
}

func (w *surfaceWatcher) Installations(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	principal *identity.Principal,
) []string {
	parts, _ := w.loadInstallations(ctx, rc, principal)
	return parts
}

func (w *surfaceWatcher) loadInstallations(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	principal *identity.Principal,
) ([]string, error) {
	if w.installations == nil || !validSurfaceInput(rc, principal) {
		return nil, nil
	}
	installations, err := w.installations.ListByPrincipal(ctx, rc.Consumer.GatewayID, principal.Subject)
	if err != nil {
		return nil, err
	}
	parts := make([]string, 0, len(installations))
	for _, installation := range installations {
		if installation == nil {
			continue
		}
		parts = append(parts, "in:"+installation.CatalogCode+":"+string(installation.Status)+"@"+installation.UpdatedAt.UTC().Format(time.RFC3339Nano))
	}
	sort.Strings(parts)
	return parts, nil
}

// loadSurface fingerprints the registries the Store exposes to the caller right
// now — the same scoping tools/list applies (installs re-checked against the
// live grants and the caller's access level). The scoper runs as the principal;
// the gateway for the live mode decision (own policy → groups → gateway default)
// rides the context the stream handler carried over from the request. Empty when
// no scoper is wired or the consumer is not the Store.
func (w *surfaceWatcher) loadSurface(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	principal *identity.Principal,
) ([]string, error) {
	if w.scoper == nil || !validSurfaceInput(rc, principal) {
		return nil, nil
	}
	scoped, err := w.scoper.Scope(identity.WithPrincipal(ctx, principal), rc)
	if err != nil {
		return nil, err
	}
	if scoped == nil {
		return nil, nil
	}
	parts := make([]string, 0, len(scoped.Registries))
	for _, registry := range scoped.Registries {
		if registry == nil {
			continue
		}
		parts = append(parts, "sf:"+registry.ID.String()+"/"+registry.Name)
	}
	sort.Strings(parts)
	return parts, nil
}

func validSurfaceInput(rc *appconsumer.RoutableConsumer, principal *identity.Principal) bool {
	return rc != nil && rc.Consumer != nil && principal != nil && strings.TrimSpace(principal.Subject) != ""
}

func forwardedSurfaceProviders(rc *appconsumer.RoutableConsumer) map[string]struct{} {
	providers := make(map[string]struct{})
	for _, registry := range rc.Registries {
		if registry == nil || !registry.IsMCP() || registry.MCPTarget == nil || registry.MCPTarget.Auth == nil {
			continue
		}
		if registry.MCPTarget.Auth.Mode == registrydomain.MCPAuthModeForwarded {
			providers[registry.MCPTarget.Auth.Provider] = struct{}{}
		}
	}
	return providers
}

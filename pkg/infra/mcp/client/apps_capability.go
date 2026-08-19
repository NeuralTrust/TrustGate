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

package client

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/version"
)

const appCapabilityNegativeTTL = 10 * time.Second

var (
	// ErrAppCapabilityUnsupported means the upstream did not positively negotiate MCP Apps.
	ErrAppCapabilityUnsupported = errors.New("mcp: upstream Apps capability unsupported")
	// ErrAppCapabilityProtocol means the upstream returned malformed Apps negotiation data.
	ErrAppCapabilityProtocol = errors.New("mcp: upstream Apps capability negotiation failed")
)

// AppCapabilityResolver resolves the MCP Apps capability of a prepared upstream target.
type AppCapabilityResolver struct {
	cache     *cache.TTLMap
	transport http.RoundTripper
	now       func() time.Time
	mu        sync.Mutex
	flights   map[string]*appCapabilityFlight
	joined    func()
}
type appCapabilityResult struct {
	capability appmcp.MCPAppsClientCapability
	err        error
	expiresAt  time.Time
}
type appCapabilityFlight struct {
	ctx     context.Context
	cancel  context.CancelFunc
	done    chan struct{}
	result  appCapabilityResult
	waiters int
}

// NewAppCapabilityResolver builds a resolver backed by the MCP Apps cache namespace.
func NewAppCapabilityResolver(capabilityCache *cache.TTLMap) *AppCapabilityResolver {
	return &AppCapabilityResolver{cache: capabilityCache, transport: sharedHTTPTransport, now: time.Now, flights: make(map[string]*appCapabilityFlight)}
}

// Resolve discovers MCP Apps support for an already credentialed target.
func (r *AppCapabilityResolver) Resolve(ctx context.Context, target appmcp.Target) (appmcp.MCPAppsClientCapability, error) {
	if err := ctx.Err(); err != nil {
		return appmcp.MCPAppsClientCapability{}, err
	}
	if target.ProtocolMode == registrydomain.MCPProtocolModeLegacy {
		return appmcp.MCPAppsClientCapability{}, ErrAppCapabilityUnsupported
	}
	key, err := appCapabilityCacheKey(target)
	if err != nil {
		return appmcp.MCPAppsClientCapability{}, err
	}
	if cached, ok := r.lookup(key); ok {
		return cached.capability, cached.err
	}
	target = cloneTarget(target)
	for {
		flight, leader := r.join(ctx, key)
		if leader {
			go r.run(key, flight, target)
		}
		select {
		case <-ctx.Done():
			if r.leave(flight) {
				<-flight.done
			}
			return appmcp.MCPAppsClientCapability{}, ctx.Err()
		case <-flight.done:
			r.leave(flight)
			if err := ctx.Err(); err != nil {
				return appmcp.MCPAppsClientCapability{}, err
			}
			if errors.Is(flight.result.err, context.Canceled) {
				continue
			}
			return flight.result.capability, flight.result.err
		}
	}
}
func (r *AppCapabilityResolver) join(ctx context.Context, key string) (*appCapabilityFlight, bool) {
	r.mu.Lock()
	flight := r.flights[key]
	leader := flight == nil
	if flight == nil {
		workCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), responseHeaderTimeout)
		flight = &appCapabilityFlight{ctx: workCtx, cancel: cancel, done: make(chan struct{})}
		r.flights[key] = flight
	}
	flight.waiters++
	r.mu.Unlock()
	if r.joined != nil {
		r.joined()
	}
	return flight, leader
}
func (r *AppCapabilityResolver) leave(flight *appCapabilityFlight) bool {
	r.mu.Lock()
	flight.waiters--
	last := flight.waiters == 0
	if last {
		flight.cancel()
	}
	r.mu.Unlock()
	return last
}
func (r *AppCapabilityResolver) run(key string, flight *appCapabilityFlight, target appmcp.Target) {
	result, ok := r.lookup(key)
	if !ok {
		result = r.discover(flight.ctx, target)
	}
	if result.err == nil || errors.Is(result.err, ErrAppCapabilityUnsupported) {
		r.cache.Set(key, result)
	}
	r.mu.Lock()
	flight.result = result
	flight.cancel()
	delete(r.flights, key)
	close(flight.done)
	r.mu.Unlock()
}
func (r *AppCapabilityResolver) lookup(key string) (appCapabilityResult, bool) {
	value, ok := r.cache.Get(key)
	if !ok {
		return appCapabilityResult{}, false
	}
	result, ok := value.(appCapabilityResult)
	if !ok || !r.now().Before(result.expiresAt) {
		r.cache.Delete(key)
		return appCapabilityResult{}, false
	}
	return result, true
}

func (r *AppCapabilityResolver) discover(ctx context.Context, target appmcp.Target) appCapabilityResult {
	client, err := newTargetHTTPClientWithTransport(target.Headers, r.transport)
	if err != nil {
		return r.result(appmcp.MCPAppsClientCapability{}, appmcp.ErrUnreachable)
	}
	probe := newStrictProbe(r.transport, []string{modernProtocolVersion}, version.Version)
	attempt, err := probe.request(ctx, client, target.URL, modernProtocolVersion, map[string]any{"extensions": map[string]any{
		appmcp.MCPAppsExtensionIdentifier: map[string]any{"mimeTypes": []string{appmcp.MCPAppsHTMLMIMEType}},
	}})
	if err != nil {
		return r.result(appmcp.MCPAppsClientCapability{}, safeAppCapabilityError(err))
	}
	outcome, _, err := probe.classify(attempt, modernProtocolVersion, true)
	if err != nil {
		return r.result(appmcp.MCPAppsClientCapability{}, safeAppCapabilityError(err))
	}
	if outcome.kind != probeModern || outcome.version != modernProtocolVersion {
		return r.result(appmcp.MCPAppsClientCapability{}, ErrAppCapabilityUnsupported)
	}
	capability, err := parseAppsCapability(attempt.result)
	return r.result(capability, err)
}

func (r *AppCapabilityResolver) result(capability appmcp.MCPAppsClientCapability, err error) appCapabilityResult {
	ttl := appCapabilityNegativeTTL
	if err == nil {
		ttl = cache.MCPAppsCacheTTL
	}
	return appCapabilityResult{capability: capability, err: err, expiresAt: r.now().Add(ttl)}
}

func safeAppCapabilityError(err error) error {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, appmcp.ErrSubscriptionAuthentication):
		return appmcp.ErrSubscriptionAuthentication
	case errors.Is(err, appmcp.ErrProtocolIncompatible):
		return ErrAppCapabilityUnsupported
	case errors.Is(err, appmcp.ErrUnreachable):
		return appmcp.ErrUnreachable
	default:
		return ErrAppCapabilityProtocol
	}
}

func parseAppsCapability(result *discoverProbeResult) (appmcp.MCPAppsClientCapability, error) {
	if result == nil || len(result.ExtensionsRaw) == 0 {
		return appmcp.MCPAppsClientCapability{}, ErrAppCapabilityUnsupported
	}
	var extensions map[string]json.RawMessage
	if json.Unmarshal(result.ExtensionsRaw, &extensions) != nil || extensions == nil {
		return appmcp.MCPAppsClientCapability{}, ErrAppCapabilityProtocol
	}
	raw, ok := extensions[appmcp.MCPAppsExtensionIdentifier]
	if !ok {
		return appmcp.MCPAppsClientCapability{}, ErrAppCapabilityUnsupported
	}
	var settings map[string]json.RawMessage
	if json.Unmarshal(raw, &settings) != nil || len(settings) != 1 {
		return appmcp.MCPAppsClientCapability{}, ErrAppCapabilityProtocol
	}
	var mimeTypes []string
	if rawMIMEs, ok := settings["mimeTypes"]; !ok ||
		json.Unmarshal(rawMIMEs, &mimeTypes) != nil || len(mimeTypes) == 0 {
		return appmcp.MCPAppsClientCapability{}, ErrAppCapabilityProtocol
	}
	for _, mimeType := range mimeTypes {
		if mimeType == appmcp.MCPAppsHTMLMIMEType {
			return appmcp.MCPAppsClientCapability{MIMETypes: []string{appmcp.MCPAppsHTMLMIMEType}}, nil
		}
	}
	return appmcp.MCPAppsClientCapability{}, ErrAppCapabilityUnsupported
}

func appCapabilityCacheKey(target appmcp.Target) (string, error) {
	origin, err := canonicalOrigin(target.URL)
	if err != nil {
		return "", appmcp.ErrUnreachable
	}
	parsed, err := url.Parse(target.URL)
	if err != nil {
		return "", appmcp.ErrUnreachable
	}
	mode := target.ProtocolMode
	if mode == "" {
		mode = registrydomain.MCPProtocolModeAuto
	}
	headers := make(map[string]string, len(target.Headers))
	for key, value := range target.Headers {
		headers[http.CanonicalHeaderKey(strings.TrimSpace(key))] = value
	}
	encoded, err := json.Marshal([]string{"mcp-apps-capability:v1", target.RegistryTargetID, origin + parsed.RequestURI(),
		target.PinKey, string(mode), modernProtocolVersion, credentialFingerprint(headers), appmcp.MCPAppsHTMLMIMEType})
	if err != nil {
		return "", ErrAppCapabilityProtocol
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

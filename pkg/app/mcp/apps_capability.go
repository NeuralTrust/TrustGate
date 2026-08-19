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
	"errors"
	"sync/atomic"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"golang.org/x/sync/errgroup"
)

// MCPAppsExtensionIdentifier is the SEP-1865 UI extension identifier.
const MCPAppsExtensionIdentifier = "io.modelcontextprotocol/ui"

// MCPAppsHTMLMIMEType is the SEP-1865 HTML resource MIME type.
const MCPAppsHTMLMIMEType = "text/html;profile=mcp-app"

const appsAdvertisementProbeBudget = 2 * time.Second

// MCPAppsClientCapability is a normalized client UI declaration.
type MCPAppsClientCapability struct {
	MIMETypes []string
}

var errMalformedMCPAppsCapability = errors.New("malformed MCP Apps capability")

// ParseMCPAppsClientCapability parses a SEP-1865 UI extension settings object.
func ParseMCPAppsClientCapability(raw any) (MCPAppsClientCapability, error) {
	settings, ok := raw.(map[string]any)
	if !ok || len(settings) != 1 {
		return MCPAppsClientCapability{}, errMalformedMCPAppsCapability
	}
	mimeTypes, ok := settings["mimeTypes"].([]any)
	if !ok || len(mimeTypes) == 0 {
		return MCPAppsClientCapability{}, errMalformedMCPAppsCapability
	}
	capability := MCPAppsClientCapability{}
	for _, value := range mimeTypes {
		mimeType, ok := value.(string)
		if !ok {
			return MCPAppsClientCapability{}, errMalformedMCPAppsCapability
		}
		if mimeType == MCPAppsHTMLMIMEType {
			capability.MIMETypes = []string{MCPAppsHTMLMIMEType}
		}
	}
	return capability, nil
}

// AppCapabilityResolver resolves Apps support for a credentialed upstream target.
type AppCapabilityResolver interface {
	Resolve(ctx context.Context, target Target) (MCPAppsClientCapability, error)
}

// AppsMediator decides whether server discovery may advertise MCP Apps.
type AppsMediator interface {
	Advertise(ctx context.Context, modern bool, rc *appconsumer.RoutableConsumer, client MCPAppsClientCapability) bool
}

type appsMediator struct {
	enabled  bool
	ready    bool
	budget   time.Duration
	creds    CredentialResolver
	resolver AppCapabilityResolver
}

// NewAppsMediator creates the fail-closed MCP Apps policy mediator.
func NewAppsMediator(enabled, ready bool, creds CredentialResolver, resolver AppCapabilityResolver) AppsMediator {
	return &appsMediator{enabled: enabled, ready: ready, budget: appsAdvertisementProbeBudget, creds: creds, resolver: resolver}
}

func (m *appsMediator) Advertise(
	ctx context.Context,
	modern bool,
	rc *appconsumer.RoutableConsumer,
	client MCPAppsClientCapability,
) bool {
	if !m.enabled || !m.ready || !modern || !supportsMCPApps(client) || rc == nil || rc.Consumer == nil ||
		m.creds == nil || m.resolver == nil {
		return false
	}
	probeCtx, cancel := context.WithTimeout(ctx, m.budget)
	defer cancel()
	var group errgroup.Group
	group.SetLimit(discoveryFanOut)
	var found atomic.Bool
	for _, reg := range mcpRegistries(rc) {
		if probeCtx.Err() != nil {
			break
		}
		if !reg.Enabled || reg.MCPTarget.ProtocolMode == registrydomain.MCPProtocolModeLegacy || !registryPermitsApps(rc, reg) {
			continue
		}
		group.Go(func() error {
			if probeCtx.Err() != nil {
				return nil
			}
			target := targetFor(probeCtx, rc, reg)
			if err := m.creds.Apply(probeCtx, rc, reg, &target); err != nil || probeCtx.Err() != nil {
				return nil
			}
			capability, err := m.resolver.Resolve(probeCtx, target)
			if err == nil && supportsMCPApps(capability) && found.CompareAndSwap(false, true) {
				cancel()
			}
			return nil
		})
	}
	_ = group.Wait()
	return ctx.Err() == nil && found.Load()
}

func supportsMCPApps(capability MCPAppsClientCapability) bool {
	return len(capability.MIMETypes) == 1 && capability.MIMETypes[0] == MCPAppsHTMLMIMEType
}

func registryPermitsApps(rc *appconsumer.RoutableConsumer, reg *registrydomain.Registry) bool {
	toolkit := rc.Consumer.Toolkit()
	if toolkit == nil {
		return true
	}
	var tools, resources bool
	for _, entry := range toolkit {
		if entry.RegistryID != reg.ID {
			continue
		}
		tools = tools || entry.Tool != ""
		resources = resources || entry.Resource != ""
	}
	return tools && resources
}

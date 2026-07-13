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

// Package cors implements a PreRequest CORS plugin that validates the request
// origin, applies CORS response headers, and short-circuits preflight requests.
package cors

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
)

// PluginName is the catalog name used in policy configuration.
const PluginName = "cors"

var _ appplugins.Plugin = (*Plugin)(nil)

// Plugin enforces a per-policy CORS policy.
type Plugin struct{}

// New builds a CORS plugin.
func New() *Plugin { return &Plugin{} }

func (p *Plugin) Name() string { return PluginName }

func (p *Plugin) MutatesRequestBody() bool { return false }

func (p *Plugin) MutatesResponseBody() bool { return false }

func (p *Plugin) MutatesMetadata() bool { return false }

func (p *Plugin) MandatoryStages() []policy.Stage {
	return []policy.Stage{policy.StagePreRequest}
}

func (p *Plugin) SupportedStages() []policy.Stage {
	return []policy.Stage{policy.StagePreRequest}
}

func (p *Plugin) SupportedProtocols() []appplugins.Protocol {
	return []appplugins.Protocol{appplugins.ProtocolLLM, appplugins.ProtocolMCP}
}

func (p *Plugin) SupportedModes() []policy.Mode {
	return []policy.Mode{policy.ModeEnforce, policy.ModeObserve}
}

func (p *Plugin) ValidateConfig(settings map[string]any) error {
	_, err := parseConfig(settings)
	return err
}

func (p *Plugin) Execute(_ context.Context, in appplugins.ExecInput) (*appplugins.Result, error) {
	cfg, err := parseConfig(in.Config.Settings)
	if err != nil {
		return nil, fmt.Errorf("cors: %w", err)
	}

	method := methodOf(in.Request)
	origin := header(in.Request, "Origin")
	blocks := appplugins.Blocks(in.Mode)
	if origin == "" {
		setCorsExtras(in.Event, CorsData{Method: method, AllowedMethods: cfg.AllowMethods, Allowed: false})
		if blocks {
			return nil, &appplugins.PluginError{StatusCode: http.StatusForbidden, Message: "invalid origin"}
		}
		appplugins.SetDecision(in.Event, in.Mode)
		return &appplugins.Result{StatusCode: http.StatusOK}, nil
	}
	if !cfg.isOriginAllowed(origin) {
		setCorsExtras(in.Event, CorsData{Origin: origin, Method: method, AllowedMethods: cfg.AllowMethods, Allowed: false})
		if blocks {
			return nil, &appplugins.PluginError{StatusCode: http.StatusForbidden, Message: "CORS: origin not allowed"}
		}
		appplugins.SetDecision(in.Event, in.Mode)
		return &appplugins.Result{StatusCode: http.StatusOK}, nil
	}

	headers := map[string][]string{
		"Access-Control-Allow-Origin": {origin},
		"Vary":                        {"Origin"},
	}
	if cfg.AllowCredentials {
		headers["Access-Control-Allow-Credentials"] = []string{"true"}
	}

	if method == http.MethodOptions {
		return p.handlePreflight(cfg, in.Mode, in.Request, headers, in.Event)
	}

	setCorsExtras(in.Event, CorsData{Origin: origin, Method: method, AllowedMethods: cfg.AllowMethods, Allowed: true})
	return &appplugins.Result{StatusCode: http.StatusOK, Headers: headers}, nil
}

// handlePreflight validates the preflight request and short-circuits with a 204
// response carrying the negotiated CORS headers.
func (p *Plugin) handlePreflight(cfg *config, mode policy.Mode, req *infracontext.RequestContext, headers map[string][]string, event *metrics.EventContext) (*appplugins.Result, error) {
	origin := header(req, "Origin")
	requestedMethod := header(req, "Access-Control-Request-Method")
	blocks := appplugins.Blocks(mode)
	if requestedMethod == "" {
		setCorsExtras(event, CorsData{Origin: origin, Method: req.Method, AllowedMethods: cfg.AllowMethods, Preflight: true, Allowed: false})
		if blocks {
			return nil, &appplugins.PluginError{
				StatusCode: http.StatusBadRequest,
				Message:    "CORS preflight missing Access-Control-Request-Method header",
				Headers:    headers,
			}
		}
		appplugins.SetDecision(event, mode)
		return &appplugins.Result{StatusCode: http.StatusOK, Headers: headers}, nil
	}
	if !cfg.isMethodAllowed(requestedMethod) {
		setCorsExtras(event, CorsData{Origin: origin, Method: req.Method, RequestedMethod: requestedMethod, AllowedMethods: cfg.AllowMethods, Preflight: true, Allowed: false})
		if blocks {
			return nil, &appplugins.PluginError{
				StatusCode: http.StatusMethodNotAllowed,
				Message:    "CORS preflight: method not allowed",
				Headers:    headers,
			}
		}
		appplugins.SetDecision(event, mode)
		return &appplugins.Result{StatusCode: http.StatusOK, Headers: headers}, nil
	}

	headers["Access-Control-Allow-Methods"] = []string{strings.Join(cfg.AllowMethods, ", ")}
	if reqHeaders := header(req, "Access-Control-Request-Headers"); reqHeaders != "" {
		headers["Access-Control-Allow-Headers"] = []string{reqHeaders}
	} else {
		headers["Access-Control-Allow-Headers"] = []string{"Content-Type"}
	}
	if len(cfg.ExposeHeaders) > 0 {
		headers["Access-Control-Expose-Headers"] = []string{strings.Join(cfg.ExposeHeaders, ", ")}
	}
	if cfg.MaxAge != "" {
		headers["Access-Control-Max-Age"] = []string{cfg.MaxAge}
	}

	setCorsExtras(event, CorsData{Origin: origin, Method: req.Method, RequestedMethod: requestedMethod, AllowedMethods: cfg.AllowMethods, Preflight: true, Allowed: true})
	// A successful preflight is a short-circuit, not an error: return 204 with
	// no body and the negotiated headers.
	return &appplugins.Result{
		StatusCode:   http.StatusNoContent,
		Headers:      headers,
		StopUpstream: true,
	}, nil
}

func setCorsExtras(event *metrics.EventContext, data CorsData) {
	if event == nil {
		return
	}
	event.SetExtras(data)
}

func header(req *infracontext.RequestContext, name string) string {
	if req == nil {
		return ""
	}
	if values, ok := req.Headers[name]; ok && len(values) > 0 {
		return values[0]
	}
	return ""
}

func methodOf(req *infracontext.RequestContext) string {
	if req == nil {
		return ""
	}
	return req.Method
}

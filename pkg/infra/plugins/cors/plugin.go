// Package cors implements a PreRequest CORS plugin that validates the request
// origin, applies CORS response headers, and short-circuits preflight requests.
package cors

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	appplugins "github.com/NeuralTrust/AgentGateway/pkg/app/plugins"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/metrics"
)

// PluginName is the catalog name used in policy configuration.
const PluginName = "cors"

var _ appplugins.Plugin = (*Plugin)(nil)

// Plugin enforces a per-policy CORS policy.
type Plugin struct{}

// New builds a CORS plugin.
func New() *Plugin { return &Plugin{} }

func (p *Plugin) Name() string { return PluginName }

func (p *Plugin) MandatoryStages() []policy.Stage {
	return []policy.Stage{policy.StagePreRequest}
}

func (p *Plugin) SupportedStages() []policy.Stage {
	return []policy.Stage{policy.StagePreRequest}
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
	if origin == "" {
		setCorsExtras(in.Event, CorsData{Method: method, AllowedMethods: cfg.AllowMethods, Allowed: false})
		return nil, &appplugins.PluginError{StatusCode: http.StatusForbidden, Message: "invalid origin"}
	}
	if !cfg.isOriginAllowed(origin) {
		setCorsExtras(in.Event, CorsData{Origin: origin, Method: method, AllowedMethods: cfg.AllowMethods, Allowed: false})
		return nil, &appplugins.PluginError{StatusCode: http.StatusForbidden, Message: "CORS: origin not allowed"}
	}

	headers := map[string][]string{
		"Access-Control-Allow-Origin": {origin},
		"Vary":                        {"Origin"},
	}
	if cfg.AllowCredentials {
		headers["Access-Control-Allow-Credentials"] = []string{"true"}
	}

	if method == http.MethodOptions {
		return p.handlePreflight(cfg, in.Request, headers, in.Event)
	}

	setCorsExtras(in.Event, CorsData{Origin: origin, Method: method, AllowedMethods: cfg.AllowMethods, Allowed: true})
	return &appplugins.Result{StatusCode: http.StatusOK, Headers: headers}, nil
}

// handlePreflight validates the preflight request and short-circuits with a 204
// response carrying the negotiated CORS headers.
func (p *Plugin) handlePreflight(cfg *config, req *infracontext.RequestContext, headers map[string][]string, event *metrics.EventContext) (*appplugins.Result, error) {
	origin := header(req, "Origin")
	requestedMethod := header(req, "Access-Control-Request-Method")
	if requestedMethod == "" {
		setCorsExtras(event, CorsData{Origin: origin, Method: req.Method, AllowedMethods: cfg.AllowMethods, Preflight: true, Allowed: false})
		return nil, &appplugins.PluginError{
			StatusCode: http.StatusBadRequest,
			Message:    "CORS preflight missing Access-Control-Request-Method header",
			Headers:    headers,
		}
	}
	if !cfg.isMethodAllowed(requestedMethod) {
		setCorsExtras(event, CorsData{Origin: origin, Method: req.Method, RequestedMethod: requestedMethod, AllowedMethods: cfg.AllowMethods, Preflight: true, Allowed: false})
		return nil, &appplugins.PluginError{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "CORS preflight: method not allowed",
			Headers:    headers,
		}
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

// Package requestsize implements a PreRequest plugin that rejects requests
// whose body exceeds configured byte or character limits.
package requestsize

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"unicode/utf8"

	appplugins "github.com/NeuralTrust/AgentGateway/pkg/app/plugins"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
)

// PluginName is the catalog name used in policy configuration.
const PluginName = "request_size_limiter"

var _ appplugins.Plugin = (*Plugin)(nil)

// Plugin enforces request body size limits.
type Plugin struct{}

// New builds a request size limiter.
func New() *Plugin { return &Plugin{} }

func (p *Plugin) Name() string { return PluginName }

func (p *Plugin) Stages() []policy.Stage {
	return []policy.Stage{policy.StagePreRequest}
}

func (p *Plugin) ValidateConfig(settings map[string]any) error {
	_, err := parseConfig(settings)
	return err
}

func (p *Plugin) Execute(_ context.Context, in appplugins.ExecInput) (*appplugins.Result, error) {
	cfg, err := parseConfig(in.Config.Settings)
	if err != nil {
		return nil, fmt.Errorf("request_size_limiter: %w", err)
	}

	if cfg.RequireContentLength && contentLength(in.Request) == "" {
		return nil, &appplugins.PluginError{
			StatusCode: http.StatusLengthRequired,
			Message:    "Content-Length header is required",
		}
	}

	var body []byte
	if in.Request != nil {
		body = in.Request.Body
	}

	maxBytes := cfg.maxSizeBytes()
	byteSize := len(body)
	if byteSize > maxBytes {
		return nil, &appplugins.PluginError{
			StatusCode: http.StatusRequestEntityTooLarge,
			Message:    fmt.Sprintf("request size limit exceeded: received %d bytes", byteSize),
		}
	}

	charCount := utf8.RuneCount(body)
	if int64(charCount) > cfg.MaxCharsPerRequest {
		return nil, &appplugins.PluginError{
			StatusCode: http.StatusRequestEntityTooLarge,
			Message:    fmt.Sprintf("character limit exceeded: received %d characters", charCount),
		}
	}

	return &appplugins.Result{
		StatusCode: http.StatusOK,
		Headers: map[string][]string{
			"X-Request-Size-Bytes": {strconv.Itoa(byteSize)},
			"X-Request-Size-Chars": {strconv.Itoa(charCount)},
			"X-Size-Limit-Bytes":   {strconv.Itoa(maxBytes)},
			"X-Size-Limit-Chars":   {strconv.FormatInt(cfg.MaxCharsPerRequest, 10)},
		},
	}, nil
}

func contentLength(req *infracontext.RequestContext) string {
	if req == nil {
		return ""
	}
	if values, ok := req.Headers["Content-Length"]; ok && len(values) > 0 {
		return values[0]
	}
	return ""
}

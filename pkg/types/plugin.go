package types

import (
	"context"
	"net/url"

	"github.com/valyala/fasthttp"
)

// Stage represents when a plugin should be executed
type Stage string

const (
	PreRequest   Stage = "pre_request"
	PostRequest  Stage = "post_request"
	PreResponse  Stage = "pre_response"
	PostResponse Stage = "post_response"
)

// Level represents at which level the plugin is configured
type Level string

const (
	GatewayLevel Level = "gateway"
	RuleLevel    Level = "rule"
)

// PluginConfig represents the configuration for a plugin
type PluginConfig struct {
	ID       string                 `json:"id"` // ID of the gateway or rule this plugin belongs to
	Name     string                 `json:"name"`
	Enabled  bool                   `json:"enabled"`
	Level    Level                  `json:"level"`
	Stage    Stage                  `json:"stage"`
	Priority int                    `json:"priority"`
	Parallel bool                   `json:"parallel"` // Whether this plugin can run in parallel
	Settings map[string]interface{} `json:"settings"`
}

type PluginError struct {
	StatusCode int
	Message    string
	Err        error
}

type PluginResponse struct {
	StatusCode int
	Message    string
	Body       []byte
	Headers    map[string][]string
	Metadata   map[string]interface{}
}

func (e *PluginError) Error() string {
	return e.Message
}

// PluginChain represents a sequence of plugins to be executed
type PluginChain struct {
	Stage    Stage          `json:"stage"`
	Parallel bool           `json:"parallel"`
	Plugins  []PluginConfig `json:"plugins"`
}

// RequestContext represents the context for a request
type RequestContext struct {
	Context     context.Context
	FasthttpCtx *fasthttp.RequestCtx
	GatewayID   string
	RuleID      string
	Headers     map[string][]string
	Method      string
	Path        string
	Query       url.Values
	Body        []byte
	Metadata    map[string]interface{}
	Stage       Stage // Current execution stage
}

// ResponseContext represents the context for a response
type ResponseContext struct {
	Context        context.Context
	GatewayID      string
	Headers        map[string][]string
	Body           []byte
	StatusCode     int
	Metadata       map[string]interface{}
	Streaming      bool
	StopProcessing bool
}

// RateLimiterConfig represents the configuration for rate limiting
type RateLimiterConfig struct {
	Limits  map[string]RateLimit `json:"limits"`
	Actions RateLimiterActions   `json:"actions"`
}

type RateLimit struct {
	Limit  int    `json:"limit"`
	Window string `json:"window"`
}

type RateLimiterActions struct {
	Type       string `json:"type"`
	RetryAfter string `json:"retry_after"`
}

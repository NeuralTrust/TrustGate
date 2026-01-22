package types

import (
	"errors"
	"fmt"
)

var (
	ErrRequiredPluginNotFound     = errors.New("plugin is required")
	ErrDuplicateTelemetryExporter = errors.New("duplicate telemetry exporter provider")
	ErrTelemetryValidation        = errors.New("failed to validate telemetry providers")
	ErrUnknownPlugin              = errors.New("unknown plugin")
	ErrPluginChainValidation      = errors.New("failed to validate plugin chain")
)

// Stage represents when a plugin should be executed
type Stage string

const (
	PreRequest   Stage = "pre_request"
	PostRequest  Stage = "post_request"
	PreResponse  Stage = "pre_response"
	PostResponse Stage = "post_response"

	ModeObserve string = "observe"
	ModeEnforce string = "enforce"
)

// PluginConfig represents the configuration for a plugin
type PluginConfig struct {
	ID       string                 `json:"id"` // ID of the gateway or rule this plugin belongs to
	Name     string                 `json:"name"`
	Enabled  bool                   `json:"enabled"`
	Stage    Stage                  `json:"stage"`
	Priority int                    `json:"priority"`
	Parallel bool                   `json:"parallel"` // Whether this plugin can run in parallel
	Settings map[string]interface{} `json:"settings"`
}

type PluginError struct {
	StatusCode int    `json:"code"`
	Message    string `json:"message"`
	Err        error  `json:"-"`
	Headers    map[string][]string
	Metadata   map[string]interface{}
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

type PluginChain struct {
	Stage    Stage          `json:"stage"`
	Parallel bool           `json:"parallel"`
	Plugins  []PluginConfig `json:"plugins"`
}

type BasePlugin struct {
}

func NewBasePlugin() *BasePlugin {
	return &BasePlugin{}
}

func (p *BasePlugin) ValidateMode(mode string) error {
	if mode == "" {
		// Empty mode is valid, default will be applied in Execute
		return nil
	}
	if mode != ModeObserve && mode != ModeEnforce {
		return fmt.Errorf("mode must be either observe or enforce")
	}
	return nil
}

package mcp

import (
	"fmt"

	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
)

var (
	// ErrToolNotFound means the requested tool is not part of the consumer's
	// composed virtual MCP surface.
	ErrToolNotFound = fmt.Errorf("mcp: tool not found: %w", commonerrors.ErrNotFound)
	// ErrNoMCPRegistries means the consumer has no MCP registries attached.
	ErrNoMCPRegistries = fmt.Errorf("mcp: no MCP registries attached to consumer: %w", commonerrors.ErrValidation)
	// ErrUpstreamUnavailable means a required upstream MCP server could not be
	// reached (respecting the consumer's fail_mode).
	ErrUpstreamUnavailable = fmt.Errorf("mcp: upstream unavailable")
)

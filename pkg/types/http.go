package types

import (
	"context"
	"net/url"
	"time"

	"github.com/gofiber/fiber/v2"
)

// RequestContext represents the context for a request
type RequestContext struct {
	C         *fiber.Ctx
	Context   context.Context
	GatewayID string
	RuleID    string
	Headers   map[string][]string
	Method    string
	Path      string
	Query     url.Values
	Body      []byte
	Metadata  map[string]interface{}
	Stage     Stage
	ProcessAt *time.Time
	IP        string
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
	ProcessAt      *time.Time
	Target         *UpstreamTarget
}

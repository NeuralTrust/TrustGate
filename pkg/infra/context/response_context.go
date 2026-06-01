package context

import (
	"context"
	"time"
)

type ResponseContext struct {
	Context       context.Context
	GatewayID     string
	BackendID     string
	Headers       map[string][]string
	Body          []byte
	StatusCode    int
	Streaming     bool
	TargetLatency float64
	ProcessAt     *time.Time
	// Metadata carries values plugins pass across stages within a single
	// request (e.g. cache status on PreRequest read back on PostResponse).
	Metadata map[string]interface{}
}

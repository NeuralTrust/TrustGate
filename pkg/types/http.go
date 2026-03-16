package types

import (
	"context"
	"net/url"
	"sync"
	"time"

	pluginTypes "github.com/NeuralTrust/TrustGate/pkg/infra/plugins/types"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/gofiber/fiber/v2"
)

// RequestContext represents the context for a request
type RequestContext struct {
	C            *fiber.Ctx
	Context      context.Context
	GatewayID    string
	RuleID       string
	Headers      map[string][]string
	Method       string
	Path         string
	Query        url.Values
	Body         []byte
	Messages     []string
	Metadata     map[string]interface{}
	Stage        pluginTypes.Stage
	ProcessAt    *time.Time
	IP           string
	SessionID    string
	Provider     string
	SourceFormat string
	TargetFormat string

	canonicalReq  *adapter.CanonicalRequest
	canonicalOnce sync.Once
	canonicalErr  error

	sourceAdapter     adapter.ProviderAdapter
	sourceAdapterOnce sync.Once
	sourceAdapterErr  error

	adapterReg *adapter.Registry
}

// SetAdapterRegistry configures the adapter registry for lazy canonical decoding.
func (r *RequestContext) SetAdapterRegistry(reg *adapter.Registry) {
	r.adapterReg = reg
}

func (r *RequestContext) CanonicalRequest() (*adapter.CanonicalRequest, error) {
	if r.Provider == "" || r.adapterReg == nil {
		return nil, nil
	}
	r.canonicalOnce.Do(func() {
		format := adapter.Format(r.SourceFormat)
		if format == "" {
			format = adapter.DetectFormat(r.Body)
		}
		r.canonicalReq, r.canonicalErr = r.adapterReg.DecodeRequestFor(r.Body, format)
	})
	return r.canonicalReq, r.canonicalErr
}

// SourceAdapter returns the ProviderAdapter for the source (client-side) format.
// Plugins must encode back to this format so the handler can later adapt to the
// target format if needed.
func (r *RequestContext) SourceAdapter() (adapter.ProviderAdapter, error) {
	if r.Provider == "" || r.adapterReg == nil {
		return nil, nil
	}
	r.sourceAdapterOnce.Do(func() {
		format := adapter.Format(r.SourceFormat)
		if format == "" {
			format = adapter.DetectFormat(r.Body)
		}
		r.sourceAdapter, r.sourceAdapterErr = r.adapterReg.GetAdapter(format)
	})
	return r.sourceAdapter, r.sourceAdapterErr
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
	Target         *UpstreamTargetDTO
	Rule           *ForwardingRuleDTO
	TargetLatency  float64
	SourceFormat   string

	canonicalResp *adapter.CanonicalResponse
	canonicalOnce sync.Once
	canonicalErr  error
	adapterReg    *adapter.Registry
}

// SetAdapterRegistry configures the adapter registry for lazy canonical decoding.
func (r *ResponseContext) SetAdapterRegistry(reg *adapter.Registry) {
	r.adapterReg = reg
}

func (r *ResponseContext) CanonicalResponse() (*adapter.CanonicalResponse, error) {
	if r.adapterReg == nil || r.SourceFormat == "" {
		return nil, nil
	}
	r.canonicalOnce.Do(func() {
		r.canonicalResp, r.canonicalErr = r.adapterReg.DecodeResponseFor(
			r.Body, adapter.Format(r.SourceFormat),
		)
	})
	return r.canonicalResp, r.canonicalErr
}

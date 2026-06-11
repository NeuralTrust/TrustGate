package context

import (
	"context"
	"net/url"
	"strings"
	"time"
)

type Attachment struct {
	Filename    string
	ContentType string
	Data        []byte
}

type RequestContext struct {
	Context            context.Context
	GatewayID          string
	ConsumerID         string
	RegistryID         string
	Headers            map[string][]string
	Method             string
	Path               string
	Query              url.Values
	Body               []byte
	Messages           []string
	Attachments        []Attachment
	Metadata           map[string]interface{}
	ProcessAt          *time.Time
	IP                 string
	SessionID          string
	PreviousResponseID string
	Provider           string
	SourceFormat       string
	TargetFormat       string
	AllowedModels      []string
	DefaultModel       string
	RequestedModel     string
}

// HeaderValue returns the first non-empty value of the named header, matched
// case-insensitively. It returns "" when the header is absent or empty.
func (r *RequestContext) HeaderValue(name string) string {
	if r == nil || name == "" || len(r.Headers) == 0 {
		return ""
	}
	if values, ok := r.Headers[name]; ok && len(values) > 0 && values[0] != "" {
		return values[0]
	}
	for headerName, values := range r.Headers {
		if strings.EqualFold(headerName, name) && len(values) > 0 && values[0] != "" {
			return values[0]
		}
	}
	return ""
}

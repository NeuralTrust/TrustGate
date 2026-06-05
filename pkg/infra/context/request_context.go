package context

import (
	"context"
	"net/url"
	"time"
)

type Attachment struct {
	Filename    string
	ContentType string
	Data        []byte
}

type RequestContext struct {
	Context       context.Context
	GatewayID     string
	RegistryID    string
	Headers       map[string][]string
	Method        string
	Path          string
	Query         url.Values
	Body          []byte
	Messages      []string
	Attachments   []Attachment
	Metadata      map[string]interface{}
	ProcessAt     *time.Time
	IP            string
	SessionID     string
	Provider      string
	SourceFormat  string
	TargetFormat  string
	AllowedModels []string
	DefaultModel  string
}

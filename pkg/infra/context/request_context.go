// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package context

import (
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
	GatewayID          string
	ConsumerID         string
	ConsumerType       string
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

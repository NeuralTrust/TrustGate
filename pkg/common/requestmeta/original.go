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

package requestmeta

import (
	"context"
	"net/http"
	"strings"
)

type OriginalRequest struct {
	IP      string              `json:"ip,omitempty"`
	Headers map[string][]string `json:"headers,omitempty"`
}

type contextKey struct{}

func NewContext(ctx context.Context, ip string, headers map[string][]string) context.Context {
	return context.WithValue(ctx, contextKey{}, OriginalRequest{IP: strings.Clone(ip), Headers: metadataHeaders(headers)})
}

func FromContext(ctx context.Context) *OriginalRequest {
	value, ok := ctx.Value(contextKey{}).(OriginalRequest)
	if !ok {
		return nil
	}
	value.Headers = metadataHeaders(value.Headers)
	return &value
}

func metadataHeaders(headers map[string][]string) map[string][]string {
	out := make(map[string][]string)
	for key, values := range headers {
		key = strings.Clone(http.CanonicalHeaderKey(key))
		switch key {
		case "Accept", "Content-Type", "User-Agent", "X-Request-Id":
			for _, value := range values {
				if len(out[key]) < 4 && len(value) <= 512 && !strings.ContainsAny(value, "\r\n") {
					out[key] = append(out[key], strings.Clone(value))
				}
			}
		}
	}
	return out
}

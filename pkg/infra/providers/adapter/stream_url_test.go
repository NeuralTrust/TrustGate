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

package adapter

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestURLRequestsStream(t *testing.T) {
	tests := []struct {
		name  string
		path  string
		query url.Values
		want  bool
	}{
		{"stream action", "/v1beta/models/gemini-2.0-flash:streamGenerateContent", nil, true},
		{"vertex stream action", "/v1/projects/p/locations/l/publishers/google/models/m:streamGenerateContent", nil, true},
		{"alt=sse", "/v1beta/models/gemini-2.0-flash:generateContent", url.Values{"alt": {"sse"}}, true},
		{"buffered action", "/v1beta/models/gemini-2.0-flash:generateContent", nil, false},
		{"word without the action colon", "/v1/streamGenerateContent", nil, false},
		{"other alt", "/v1beta/models/m:generateContent", url.Values{"alt": {"json"}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, URLRequestsStream(tt.path, tt.query))
		})
	}
}

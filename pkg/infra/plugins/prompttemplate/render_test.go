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

package prompttemplate

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRenderTemplate(t *testing.T) {
	tests := []struct {
		name        string
		tmpl        string
		vars        map[string]string
		want        string
		wantMissing []string
	}{
		{
			name:        "basic substitution",
			tmpl:        "hello {{name}}",
			vars:        map[string]string{"name": "world"},
			want:        "hello world",
			wantMissing: []string{},
		},
		{
			name:        "whitespace tolerance",
			tmpl:        "hello {{ name }}",
			vars:        map[string]string{"name": "world"},
			want:        "hello world",
			wantMissing: []string{},
		},
		{
			name:        "dotted and dashed names",
			tmpl:        "{{consumer.tier}}-{{user-id}}",
			vars:        map[string]string{"consumer.tier": "gold", "user-id": "42"},
			want:        "gold-42",
			wantMissing: []string{},
		},
		{
			name:        "unknown placeholder reported and blanked",
			tmpl:        "hi {{known}} {{unknown}}",
			vars:        map[string]string{"known": "ok"},
			want:        "hi ok ",
			wantMissing: []string{"unknown"},
		},
		{
			name:        "missing keys sorted and deduped",
			tmpl:        "{{b}} {{a}} {{b}}",
			vars:        map[string]string{},
			want:        "  ",
			wantMissing: []string{"a", "b"},
		},
		{
			name:        "no placeholder passthrough",
			tmpl:        "static content",
			vars:        map[string]string{"name": "ignored"},
			want:        "static content",
			wantMissing: []string{},
		},
		{
			name:        "repeated placeholder",
			tmpl:        "{{x}} and {{x}}",
			vars:        map[string]string{"x": "v"},
			want:        "v and v",
			wantMissing: []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, missing := renderTemplate(tt.tmpl, tt.vars)
			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.wantMissing, missing)
		})
	}
}

func TestEscapeControlChars(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "preserves newline and tab", in: "a\nb\tc", want: "a\nb\tc"},
		{name: "strips null and bell", in: "a\x00b\x07c", want: "abc"},
		{name: "strips carriage return", in: "a\rb", want: "ab"},
		{name: "keeps printable unicode", in: "café 🚀", want: "café 🚀"},
		{name: "keeps del byte", in: "a\x7fb", want: "a\x7fb"},
		{name: "no control chars passthrough", in: "plain text", want: "plain text"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, escapeControlChars(tt.in))
		})
	}
}

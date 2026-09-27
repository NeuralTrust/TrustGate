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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseImageURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		raw    string
		detail string
		want   CanonicalImage
	}{
		{
			name: "png data uri",
			raw:  "data:image/png;base64,iVBORw0KGgo=",
			want: CanonicalImage{MediaType: "image/png", Data: "iVBORw0KGgo="},
		},
		{
			name: "jpg normalized to jpeg",
			raw:  "data:image/jpg;base64,/9j/4AAQ",
			want: CanonicalImage{MediaType: "image/jpeg", Data: "/9j/4AAQ"},
		},
		{
			name: "uppercase media type",
			raw:  "data:IMAGE/PNG;base64,AAAA",
			want: CanonicalImage{MediaType: "image/png", Data: "AAAA"},
		},
		{
			name: "extra parameters before base64",
			raw:  "data:image/webp;charset=utf-8;base64,UklGR",
			want: CanonicalImage{MediaType: "image/webp", Data: "UklGR"},
		},
		{
			name: "data uri without base64 kept as url",
			raw:  "data:image/png,rawbytes",
			want: CanonicalImage{URL: "data:image/png,rawbytes"},
		},
		{
			name: "data uri without payload kept as url",
			raw:  "data:image/png;base64,",
			want: CanonicalImage{URL: "data:image/png;base64,"},
		},
		{
			name: "data uri without media type kept as url",
			raw:  "data:;base64,AAAA",
			want: CanonicalImage{URL: "data:;base64,AAAA"},
		},
		{
			name: "empty",
			raw:  "",
			want: CanonicalImage{},
		},
		{
			name:   "https with detail",
			raw:    "https://example.com/cat.jpg",
			detail: "low",
			want:   CanonicalImage{URL: "https://example.com/cat.jpg", Detail: "low"},
		},
		{
			name:   "data uri keeps detail",
			raw:    "data:image/gif;base64,R0lG",
			detail: "high",
			want:   CanonicalImage{MediaType: "image/gif", Data: "R0lG", Detail: "high"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, parseImageURL(tt.raw, tt.detail))
		})
	}
}

func TestCanonicalImage_DataURIRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []string{
		"data:image/png;base64,iVBORw0KGgo=",
		"data:image/jpeg;base64,/9j/4AAQ",
		"data:image/gif;base64,R0lG",
		"data:image/webp;base64,UklGR",
		"https://example.com/cat.jpg",
		"data:image/png,rawbytes",
	}

	for _, raw := range tests {
		t.Run(raw, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, raw, parseImageURL(raw, "").dataURI())
		})
	}
}

func TestIsHTTPImageURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
		want bool
	}{
		{name: "http", raw: "http://example.com/a.png", want: true},
		{name: "https", raw: "https://example.com/a.png", want: true},
		{name: "uppercase scheme", raw: "HTTPS://example.com/a.png", want: true},
		{name: "ftp", raw: "ftp://example.com/a.png", want: false},
		{name: "file", raw: "file:///etc/passwd", want: false},
		{name: "no host", raw: "https:///a.png", want: false},
		{name: "data uri", raw: "data:image/png,rawbytes", want: false},
		{name: "empty", raw: "", want: false},
		{name: "unparseable", raw: "https://exa mple.com/%zz", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, isHTTPImageURL(tt.raw))
		})
	}
}

func TestNormalizeImageMediaType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in   string
		want string
	}{
		{in: "image/jpg", want: "image/jpeg"},
		{in: " Image/JPG ", want: "image/jpeg"},
		{in: "IMAGE/PNG", want: "image/png"},
		{in: "image/webp", want: "image/webp"},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, normalizeImageMediaType(tt.in))
		})
	}
}

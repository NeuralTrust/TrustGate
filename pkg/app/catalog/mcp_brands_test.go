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

package catalog

import (
	"errors"
	"io/fs"
	"strings"
	"testing"
)

func TestBrandIconURL_ResolvesVendorAndFallsBack(t *testing.T) {
	t.Parallel()

	if got := BrandIconURL("Linear"); got != "/oauth/brands/mcp/linear.svg" {
		t.Fatalf("Linear vendor = %q", got)
	}
	if got := BrandIconURL("", "app.linear/mcp", "linear-mcp"); got != "/oauth/brands/mcp/linear.svg" {
		t.Fatalf("linear provider = %q", got)
	}
	if got := BrandIconURL("GitHub"); got != "/oauth/brands/github.svg" {
		t.Fatalf("GitHub vendor = %q", got)
	}
	if got := BrandIconURL("Google Drive"); got != "/oauth/brands/mcp/googledrive.svg" {
		t.Fatalf("Google Drive vendor = %q", got)
	}
	for vendor, want := range map[string]string{
		"AWS":       "/oauth/brands/mcp/aws.svg",
		"Holded":    "/oauth/brands/mcp/holded.png",
		"Jotform":   "/oauth/brands/mcp/jotform.svg",
		"Outlook":   "/oauth/brands/mcp/microsoft.ico",
		"Storyblok": "/oauth/brands/mcp/storyblok.png",
	} {
		if got := BrandIconURL(vendor); got != want {
			t.Fatalf("%s vendor = %q, want %q", vendor, got, want)
		}
	}
	if got := BrandIconURL("unknown-custom"); got != "/oauth/brands/mcp.svg" {
		t.Fatalf("unknown vendor = %q", got)
	}
}

func TestReadBrandIcon_ServesMappedAssets(t *testing.T) {
	t.Parallel()

	data, ct, err := ReadBrandIcon("mcp/linear.svg")
	if err != nil {
		t.Fatalf("read linear: %v", err)
	}
	if !strings.HasPrefix(ct, "image/svg") {
		t.Fatalf("content type = %q", ct)
	}
	if !strings.Contains(string(data), "<svg") {
		t.Fatal("linear logo is not an SVG")
	}

	drive, _, err := ReadBrandIcon("mcp/googledrive.svg")
	if err != nil {
		t.Fatalf("read googledrive: %v", err)
	}
	if strings.Contains(string(drive), `fill="#1FA463"`) {
		t.Fatal("Drive logo must not be the monochrome Simple Icons green")
	}
	for _, color := range []string{"#0066da", "#00ac47", "#ffba00"} {
		if !strings.Contains(string(drive), color) {
			t.Fatalf("Drive logo missing official color %s", color)
		}
	}

	for _, name := range []string{"mcp/aws.svg", "mcp/holded.png", "mcp/jotform.svg", "mcp/storyblok.png"} {
		data, contentType, err := ReadBrandIcon(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if len(data) == 0 {
			t.Fatalf("%s is empty", name)
		}
		if !strings.HasPrefix(contentType, "image/") {
			t.Fatalf("%s content type = %q", name, contentType)
		}
	}

	if _, _, err := ReadBrandIcon("../mcp_brands.go"); err == nil {
		t.Fatal("path traversal must not read outside brands/")
	} else if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("path traversal error = %v", err)
	}
}

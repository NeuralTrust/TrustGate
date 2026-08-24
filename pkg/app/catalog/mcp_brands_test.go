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

	if _, _, err := ReadBrandIcon("../mcp_brands.go"); err == nil {
		t.Fatal("path traversal must not read outside brands/")
	} else if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("path traversal error = %v", err)
	}
}

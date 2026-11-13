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

package filestore_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/secretstore"
	"github.com/NeuralTrust/TrustGate/pkg/infra/secretstore/filestore"
)

func setup(t *testing.T) (root, outside string) {
	t.Helper()
	base := t.TempDir()
	root = filepath.Join(base, "secrets")
	outside = filepath.Join(base, "secrets2")
	for _, dir := range []string{filepath.Join(root, "llm", "..2026"), outside} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	write := func(path, body string) {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(root, "llm", "..2026", "openai"), "sk-live\n")
	if err := os.Symlink(filepath.Join("..2026", "openai"), filepath.Join(root, "llm", "openai")); err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(root, "llm", "crlf"), "sk-crlf\r\n")
	write(filepath.Join(root, "llm", "json"), `{"key":"sk-json"}`)
	write(filepath.Join(outside, "stolen"), "nope")
	if err := os.Symlink(filepath.Join(outside, "stolen"), filepath.Join(root, "llm", "escape")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../secrets2/stolen", filepath.Join(root, "llm", "relative-escape")); err != nil {
		t.Fatal(err)
	}
	return root, outside
}

func TestFetch(t *testing.T) {
	t.Parallel()
	root, _ := setup(t)
	b := filestore.New(&secretstore.FileConfig{Root: root})
	ctx := context.Background()

	for path, want := range map[string]string{"llm/openai": "sk-live", "llm/crlf": "sk-crlf"} {
		s, err := b.Fetch(ctx, path, "")
		if err != nil {
			t.Fatalf("Fetch(%s): %v", path, err)
		}
		if v, _ := s.Select(""); v != want {
			t.Fatalf("Fetch(%s) = %q, want %q", path, v, want)
		}
	}
	s, err := b.Fetch(ctx, "llm/json", "")
	if err != nil {
		t.Fatal(err)
	}
	if v, err := s.Select("key"); err != nil || v != "sk-json" {
		t.Fatalf("JSON field = %q, %v", v, err)
	}

	tests := map[string]error{
		"llm/missing":         secretstore.ErrNotFound,
		"llm":                 secretstore.ErrNotFound,
		"llm/escape":          secretstore.ErrAccessDenied,
		"llm/relative-escape": secretstore.ErrAccessDenied,
	}
	for path, want := range tests {
		if _, err := b.Fetch(ctx, path, ""); !errors.Is(err, want) {
			t.Errorf("Fetch(%s) = %v, want %v", path, err, want)
		}
	}
	if _, err := b.Fetch(ctx, "llm/openai", "2"); !errors.Is(err, secretstore.ErrInvalidPayload) {
		t.Errorf("version: %v", err)
	}
}

func TestSiblingDirectoryIsOutsideTheRoot(t *testing.T) {
	t.Parallel()
	root, _ := setup(t)
	b := filestore.New(&secretstore.FileConfig{Root: root})
	if _, err := b.Fetch(context.Background(), "../secrets2/stolen", ""); !errors.Is(err, secretstore.ErrAccessDenied) {
		t.Fatalf("sibling directory: %v", err)
	}
}

func TestProbe(t *testing.T) {
	t.Parallel()
	root, _ := setup(t)
	if err := filestore.New(&secretstore.FileConfig{Root: root}).Probe(context.Background()); err != nil {
		t.Fatalf("Probe: %v", err)
	}
	missing := filestore.New(&secretstore.FileConfig{Root: filepath.Join(root, "nope")})
	if err := missing.Probe(context.Background()); secretstore.ClassOf(err) != secretstore.ClassUnavailable {
		t.Fatalf("missing root: %v", err)
	}
}

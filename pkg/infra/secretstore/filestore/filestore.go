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

// Package filestore reads secrets from files under a root directory, such as
// Kubernetes Secrets mounted as volumes or files written by the Secrets Store
// CSI driver or External Secrets Operator.
package filestore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/NeuralTrust/TrustGate/pkg/domain/secretstore"
)

// maxSecretBytes bounds a secret file read into memory.
const maxSecretBytes = 1 << 20

// Backend reads <root>/<path>. A path that resolves outside the root,
// through ".." or a symlink, is refused.
type Backend struct {
	root string
}

var _ secretstore.Backend = (*Backend)(nil)

// New returns the backend for cfg.
func New(cfg *secretstore.FileConfig) *Backend {
	return &Backend{root: filepath.Clean(cfg.Root)}
}

// Fetch implements secretstore.Backend. One trailing newline is trimmed:
// secrets created from files often end in one, and a credential with a
// newline is rejected upstream.
func (b *Backend) Fetch(ctx context.Context, path, version string) (secretstore.Secret, error) {
	if err := ctx.Err(); err != nil {
		return secretstore.Secret{}, fmt.Errorf("%w: %v", secretstore.ErrUnavailable, err)
	}
	if version != "" {
		return secretstore.Secret{}, fmt.Errorf("%w: file stores have no versions", secretstore.ErrInvalidPayload)
	}
	target, err := b.resolve(path)
	if err != nil {
		return secretstore.Secret{}, err
	}
	f, err := os.Open(target) // #nosec G304 -- confined to the store root by resolve
	if err != nil {
		return secretstore.Secret{}, classify(err)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxSecretBytes+1))
	if err != nil {
		return secretstore.Secret{}, classify(err)
	}
	if len(raw) > maxSecretBytes {
		return secretstore.Secret{}, fmt.Errorf("%w: the file is larger than %d bytes", secretstore.ErrInvalidPayload, maxSecretBytes)
	}
	if !utf8.Valid(raw) {
		return secretstore.Secret{}, fmt.Errorf("%w: the file is not UTF-8 text", secretstore.ErrInvalidPayload)
	}
	value := strings.TrimSuffix(strings.TrimSuffix(string(raw), "\n"), "\r")
	return secretstore.NewStringSecret(value, ""), nil
}

// resolve returns the real path of the file path names, after following
// every symlink, and refuses it unless it lies inside the real root.
func (b *Backend) resolve(path string) (string, error) {
	root, err := filepath.EvalSymlinks(b.root)
	if err != nil {
		return "", fmt.Errorf("%w: the store root is not readable: %v", secretstore.ErrUnavailable, err)
	}
	target, err := filepath.EvalSymlinks(filepath.Join(root, filepath.FromSlash(path)))
	if err != nil {
		return "", classify(err)
	}
	rel, err := filepath.Rel(root, target)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("%w: the path resolves outside the store root", secretstore.ErrAccessDenied)
	}
	info, err := os.Stat(target)
	if err != nil {
		return "", classify(err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("%w: the path is a directory", secretstore.ErrNotFound)
	}
	return target, nil
}

// Probe implements secretstore.Backend: the root must be a readable
// directory.
func (b *Backend) Probe(context.Context) error {
	info, err := os.Stat(b.root)
	if err != nil {
		return fmt.Errorf("%w: the store root is not readable", secretstore.ErrUnavailable)
	}
	if !info.IsDir() {
		return fmt.Errorf("%w: the store root is not a directory", secretstore.ErrUnavailable)
	}
	return nil
}

func classify(err error) error {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("%w: no such file", secretstore.ErrNotFound)
	case errors.Is(err, fs.ErrPermission):
		return fmt.Errorf("%w: the file is not readable", secretstore.ErrAccessDenied)
	default:
		return fmt.Errorf("%w: reading the file failed", secretstore.ErrUnavailable)
	}
}

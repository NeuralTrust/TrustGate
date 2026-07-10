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

package configsync

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const lkgTempPattern = ".lkg-*.tmp"

type LKGStore[T any] struct {
	crypto Crypto
	codec  SnapshotCodec[T]
	path   string
}

func NewLKGStore[T any](crypto Crypto, codec SnapshotCodec[T], path string) *LKGStore[T] {
	return &LKGStore[T]{crypto: crypto, codec: codec, path: filepath.Clean(path)}
}

func (s *LKGStore[T]) Load() (*Versioned[T], error) {
	ciphertext, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("configsync: read lkg: %w", err)
	}
	raw, err := s.crypto.Decrypt(ciphertext)
	if err != nil {
		return nil, errors.Join(ErrLKGCorrupt, fmt.Errorf("configsync: decrypt lkg: %w", err))
	}
	snapshot, err := s.codec.Decode(raw)
	if err != nil {
		return nil, errors.Join(ErrLKGCorrupt, fmt.Errorf("configsync: decode lkg: %w", err))
	}
	return &Versioned[T]{Version: s.codec.Version(raw), Snapshot: snapshot, Raw: raw}, nil
}

func (s *LKGStore[T]) Persist(v *Versioned[T]) error {
	if v == nil {
		return nil
	}
	ciphertext, err := s.crypto.Encrypt(v.Raw)
	if err != nil {
		return fmt.Errorf("configsync: encrypt lkg: %w", err)
	}

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("configsync: create lkg dir: %w", err)
	}

	tmp, err := os.CreateTemp(dir, lkgTempPattern)
	if err != nil {
		return fmt.Errorf("configsync: create temp lkg: %w", err)
	}
	tmpName := tmp.Name()
	renamed := false
	defer func() {
		if !renamed {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(ciphertext); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("configsync: write temp lkg: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("configsync: sync temp lkg: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("configsync: close temp lkg: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("configsync: rename lkg: %w", err)
	}
	renamed = true
	return syncDir(dir)
}

func (s *LKGStore[T]) Age() (time.Duration, bool) {
	info, err := os.Stat(s.path)
	if err != nil {
		return 0, false
	}
	return time.Since(info.ModTime()), true
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("configsync: open lkg dir: %w", err)
	}
	defer func() { _ = d.Close() }()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("configsync: sync lkg dir: %w", err)
	}
	return nil
}

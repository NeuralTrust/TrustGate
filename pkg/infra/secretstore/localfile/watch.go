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

package localfile

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
)

const reloadDebounce = 250 * time.Millisecond

// watch calls reload after the directory holding path changes, until ctx is
// done. A ConfigMap volume publishes a new version by swapping a symlink
// next to the file, never by writing the file, and how that swap is reported
// differs between platforms; so any event in the directory schedules a
// reload, a burst collapses into one, and a reload that finds nothing
// changed has no effect. A subPath mount is a copy that never updates: the
// file must be mounted as a directory.
func watch(ctx context.Context, path string, reload func() error, logger *slog.Logger) error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("watching the store file: %w", err)
	}
	defer w.Close()
	dir := filepath.Dir(filepath.Clean(path))
	if dir == "" {
		dir = "."
	}
	if err := w.Add(dir); err != nil {
		return fmt.Errorf("watching %s: %w", dir, err)
	}

	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case _, ok := <-w.Events:
			if !ok {
				return nil
			}
			timer.Reset(reloadDebounce)
		case err, ok := <-w.Errors:
			if !ok {
				return nil
			}
			logger.Warn("secret store file watch error", slog.String("error", err.Error()))
		case <-timer.C:
			_ = reload() // a failed reload keeps the previous stores and is logged by reload
		}
	}
}

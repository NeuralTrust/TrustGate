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
	"io"
	"log/slog"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"

	"github.com/NeuralTrust/TrustGate/pkg/domain/secretstore"
)

// DeploymentSaaS is the INSTANCE_DEPLOYMENT_TYPE of NeuralTrust's shared
// planes, which never load a store file.
const DeploymentSaaS = "saas"

// BackendFactory builds the backend of one store.
type BackendFactory func(store *secretstore.Store) (secretstore.Backend, error)

// Options configures a Catalog.
type Options struct {
	// DeploymentType is INSTANCE_DEPLOYMENT_TYPE; Open refuses DeploymentSaaS.
	DeploymentType string
	Logger         *slog.Logger
	// OnReload is called after a reload with the names of the stores that
	// were added, changed or removed, so cached values read from them are
	// dropped and references to them are resolved again.
	OnReload func(changed []string)
}

type loaded struct {
	store   *secretstore.Store
	backend secretstore.Backend
}

// Catalog is the secretstore.Catalog of the stores in one store file.
type Catalog struct {
	path     string
	build    BackendFactory
	logger   *slog.Logger
	onReload func([]string)

	reloadMu sync.Mutex

	mu      sync.RWMutex
	stores  map[string]loaded
	loadErr error
}

var _ secretstore.Catalog = (*Catalog)(nil)

// Open loads the store file at path. It fails when the file cannot be read
// or is invalid, so a plane never starts with a broken store file, and on
// NeuralTrust's shared planes.
func Open(path string, build BackendFactory, opts Options) (*Catalog, error) {
	if strings.EqualFold(strings.TrimSpace(opts.DeploymentType), DeploymentSaaS) {
		return nil, fmt.Errorf("%w: a store file is refused on a plane with INSTANCE_DEPLOYMENT_TYPE=%s", secretstore.ErrInvalidStore, DeploymentSaaS)
	}
	c := &Catalog{
		path:     path,
		build:    build,
		logger:   opts.Logger,
		onReload: opts.OnReload,
		stores:   map[string]loaded{},
	}
	if c.logger == nil {
		c.logger = slog.Default()
	}
	if _, err := c.reload(); err != nil {
		return nil, err
	}
	return c, nil
}

// Get implements secretstore.Catalog.
func (c *Catalog) Get(name string) (*secretstore.Store, secretstore.Backend, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	l, ok := c.stores[strings.ToLower(name)]
	return l.store, l.backend, ok
}

// Stores implements secretstore.Catalog.
func (c *Catalog) Stores() []*secretstore.Store {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]*secretstore.Store, 0, len(c.stores))
	for _, l := range c.stores {
		out = append(out, l.store)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// LoadError implements secretstore.Catalog.
func (c *Catalog) LoadError() error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.loadErr
}

// Reload reads the store file again. A valid file replaces the stores at
// once, keeping the backends of stores whose definition did not change; an
// invalid one keeps the previous stores and is reported by LoadError until
// a later reload succeeds.
func (c *Catalog) Reload() error {
	changed, err := c.reload()
	if err != nil {
		c.logger.Error("secret store file reload failed; keeping the previous stores",
			slog.String("path", c.path), slog.String("error", err.Error()))
		return err
	}
	if len(changed) > 0 {
		c.logger.Info("secret store file reloaded", slog.Any("changed", changed))
		if c.onReload != nil {
			c.onReload(changed)
		}
	}
	return nil
}

// reload loads the file and records the outcome in LoadError while holding
// reloadMu, so a slow failed reload cannot overwrite a later success.
func (c *Catalog) reload() ([]string, error) {
	c.reloadMu.Lock()
	defer c.reloadMu.Unlock()
	changed, err := c.load()
	if err != nil {
		c.mu.Lock()
		c.loadErr = err
		c.mu.Unlock()
	}
	return changed, err
}

func (c *Catalog) load() ([]string, error) {
	raw, err := readFile(c.path)
	if err != nil {
		return nil, err
	}
	parsed, err := Parse(raw)
	if err != nil {
		return nil, err
	}

	c.mu.RLock()
	previous := c.stores
	c.mu.RUnlock()

	next := make(map[string]loaded, len(parsed))
	var changed []string
	for _, store := range parsed {
		if old, ok := previous[store.Name]; ok && reflect.DeepEqual(old.store, store) {
			next[store.Name] = old
			continue
		}
		backend, err := c.build(store)
		if err != nil {
			return nil, fmt.Errorf("store %q: %w", store.Name, err)
		}
		next[store.Name] = loaded{store: store, backend: backend}
		changed = append(changed, store.Name)
	}
	for name := range previous {
		if _, kept := next[name]; !kept {
			changed = append(changed, name)
		}
	}
	sort.Strings(changed)

	c.mu.Lock()
	c.stores = next
	c.loadErr = nil
	c.mu.Unlock()
	return changed, nil
}

func readFile(path string) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- the operator's own SECRET_STORES_FILE
	if err != nil {
		return nil, fmt.Errorf("%w: reading the store file: %v", secretstore.ErrInvalidStore, err)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: reading the store file: %v", secretstore.ErrInvalidStore, err)
	}
	return raw, nil
}

// Watch reloads the catalog whenever the store file changes, until ctx is
// done.
func (c *Catalog) Watch(ctx context.Context) error {
	return watch(ctx, c.path, c.Reload, c.logger)
}

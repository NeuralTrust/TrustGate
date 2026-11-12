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

package secretref

import (
	"context"
	"log/slog"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/NeuralTrust/TrustGate/pkg/domain/secretstore"
)

// storeHealth is what a plane observed about one store. Only store-level
// failures count: a path that does not exist or that the store's policy
// denies says nothing about the store itself.
type storeHealth struct {
	probedAt   time.Time
	probeClass secretstore.Class

	fetchedAt  time.Time
	fetchClass secretstore.Class
}

func storeLevel(c secretstore.Class) bool {
	return c == secretstore.ClassAuthFailed || c == secretstore.ClassUnavailable
}

func (c *Cache) healthLocked(store string) *storeHealth {
	h, ok := c.health[store]
	if !ok {
		h = &storeHealth{}
		c.health[store] = h
	}
	return h
}

// recordFetchLocked keeps the last store-level outcome of a fetch. A success
// or a per-path failure both prove the store answered.
func (c *Cache) recordFetchLocked(store string, err error) {
	h := c.healthLocked(store)
	h.fetchedAt = c.now()
	h.fetchClass = ""
	if class := secretstore.ClassOf(err); storeLevel(class) {
		h.fetchClass = class
	}
}

// probeTick checks every loaded store's credentials without reading a
// secret.
func (c *Cache) probeTick(ctx context.Context) {
	stores := c.catalog.Stores()
	g := new(errgroup.Group)
	g.SetLimit(probeConcurrency)
	for _, store := range stores {
		_, backend, ok := c.catalog.Get(store.Name)
		if !ok {
			continue
		}
		g.Go(func() error {
			pctx, cancel := context.WithTimeout(ctx, c.fetchTimeout)
			defer cancel()
			err := backend.Probe(pctx)
			class := secretstore.ClassOf(err)
			c.metrics.probed(pctx, store.Type, class)
			if err != nil {
				c.logger.Warn("secret store probe failed",
					slog.String("store", store.Name), slog.String("error_class", string(class)))
			}
			c.mu.Lock()
			h := c.healthLocked(store.Name)
			h.probedAt, h.probeClass = c.now(), class
			c.mu.Unlock()
			return nil
		})
	}
	_ = g.Wait() // the goroutines never return an error
}

// Statuses implements StoreHealth. A store is config_error while the last
// reload of the store file failed, auth_failed or unavailable while its last
// probe or its most recent fetch failed that way, and ok otherwise.
func (c *Cache) Statuses() []secretstore.Status {
	stores := c.catalog.Stores()
	loadFailed := c.catalog.LoadError() != nil

	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]secretstore.Status, 0, len(stores))
	for _, store := range stores {
		st := secretstore.Status{
			Name:         store.Name,
			Type:         store.Type,
			AllowedPaths: append([]string(nil), store.AllowedPaths...),
			Gateways:     append(store.Gateways[:0:0], store.Gateways...),
			State:        secretstore.StateOK,
		}
		if h, ok := c.health[store.Name]; ok {
			st.CheckedAt = h.probedAt
			if h.fetchedAt.After(st.CheckedAt) {
				st.CheckedAt = h.fetchedAt
			}
			st.ErrorClass = h.currentClass()
			st.State = stateOf(st.ErrorClass)
		}
		if loadFailed {
			st.State = secretstore.StateConfigError
		}
		out = append(out, st)
	}
	return out
}

// currentClass is the store-level failure the newest observation reports.
func (h *storeHealth) currentClass() secretstore.Class {
	if h.fetchedAt.After(h.probedAt) {
		return h.fetchClass
	}
	if storeLevel(h.probeClass) {
		return h.probeClass
	}
	return ""
}

func stateOf(c secretstore.Class) secretstore.State {
	switch c {
	case secretstore.ClassAuthFailed:
		return secretstore.StateAuthFailed
	case secretstore.ClassUnavailable:
		return secretstore.StateUnavailable
	default:
		return secretstore.StateOK
	}
}

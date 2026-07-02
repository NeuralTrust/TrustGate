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

package modules

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/container"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	infrasnapshot "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
	configsync "github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/sync"
)

const snapshotFetchTimeout = 30 * time.Second

func ConfigSyncData(c *container.Container) error {
	if err := c.Provide(func() configsync.ConfigStore[*readmodel.Snapshot] {
		return configsync.NewMemoryStore[*readmodel.Snapshot]()
	}); err != nil {
		return err
	}
	if err := c.Provide(func() configsync.SnapshotCodec[*readmodel.Snapshot] {
		return infrasnapshot.NewCodec()
	}); err != nil {
		return err
	}
	if err := c.Provide(func(cfg *config.Config) (configsync.Crypto, error) {
		key, err := base64.StdEncoding.DecodeString(cfg.ConfigSync.LKGKey)
		if err != nil {
			return nil, fmt.Errorf("decode config-sync lkg key: %w", err)
		}
		return configsync.NewAESGCMCrypto(key)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(cfg *config.Config) configsync.ConfigFetcher {
		return configsync.NewHTTPFetcher(
			cfg.ConfigSync.SnapshotURL,
			cfg.ConfigSync.Token,
			&http.Client{Timeout: snapshotFetchTimeout},
			cfg.ConfigSync.InstanceID,
		)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(cfg *config.Config, cc cache.Client) configsync.ChangeNotifier {
		return configsync.NewRedisStreamNotifier(cc.RedisClient(), cfg.ConfigSync.StreamKey, cfg.ConfigSync.StreamMaxLen)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(crypto configsync.Crypto, codec configsync.SnapshotCodec[*readmodel.Snapshot], cfg *config.Config) *configsync.LKGStore[*readmodel.Snapshot] {
		return configsync.NewLKGStore(crypto, codec, cfg.ConfigSync.LKGPath)
	}); err != nil {
		return err
	}
	return c.Provide(func(
		fetcher configsync.ConfigFetcher,
		store configsync.ConfigStore[*readmodel.Snapshot],
		notifier configsync.ChangeNotifier,
		lkg *configsync.LKGStore[*readmodel.Snapshot],
		codec configsync.SnapshotCodec[*readmodel.Snapshot],
		logger *slog.Logger,
		cfg *config.Config,
	) *configsync.Worker[*readmodel.Snapshot] {
		return configsync.NewWorker(fetcher, store, notifier, lkg, codec, logger, configsync.WorkerConfig{PollInterval: cfg.ConfigSync.PollInterval})
	})
}

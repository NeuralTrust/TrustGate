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

	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/container"
	infrasnapshot "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot"
	configsyncgrpc "github.com/NeuralTrust/TrustGate/pkg/infra/configsync/grpc"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
	configsync "github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/sync"
)

// ConfigSyncData wires the data-plane half of the config sync: the atomic snapshot store the read
// ports resolve from, the protobuf codec, the AES-256-GCM crypto guarding the encrypted
// last-known-good, the gRPC client that dials the control plane and serves as both the snapshot
// fetcher and the change-notice stream transport, the LKG store, and the convergence worker.
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
	if err := c.Provide(func(cfg *config.Config, logger *slog.Logger) (*configsyncgrpc.Client, error) {
		return configsyncgrpc.NewClient(cfg.ConfigSync, logger)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(client *configsyncgrpc.Client) configsync.ConfigFetcher {
		return client
	}); err != nil {
		return err
	}
	if err := c.Provide(func(client *configsyncgrpc.Client) configsync.StreamTransport {
		return client
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
		transport configsync.StreamTransport,
		lkg *configsync.LKGStore[*readmodel.Snapshot],
		codec configsync.SnapshotCodec[*readmodel.Snapshot],
		logger *slog.Logger,
		cfg *config.Config,
	) *configsync.Worker[*readmodel.Snapshot] {
		return configsync.NewWorker(fetcher, store, transport, lkg, codec, logger, configsync.WorkerConfig{
			PollInterval: cfg.ConfigSync.PollInterval,
			MinBackoff:   cfg.ConfigSync.GRPCMinBackoff,
			MaxBackoff:   cfg.ConfigSync.GRPCMaxBackoff,
		})
	})
}

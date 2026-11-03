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

package database

import (
	"context"
	"log/slog"

	"github.com/NeuralTrust/TrustGate/pkg/config"
)

func NewConnectionProvider(ctx context.Context, cfg *config.DatabaseConfig, logger *slog.Logger) (*Connection, error) {
	conn, err := NewConnection(ctx, cfg)
	if err != nil {
		return nil, err
	}
	logSessionIdentity(ctx, conn.Pool, logger)
	return conn, nil
}

func NewMigrationsManagerProvider(conn *Connection, cfg *config.DatabaseConfig, logger *slog.Logger) *MigrationsManager {
	return NewMigrationsManager(conn.Pool).WithOwnerRole(cfg.Role, logger)
}

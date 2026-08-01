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

package vault

import (
	"context"
	"log/slog"
	"strings"

	"github.com/redis/go-redis/v9"
)

// WarnIfVolatile inspects the Redis instance that backs the data-plane vault
// and logs, once at startup, every way it could silently drop the durable OAuth
// state stored in it (user credentials, DCR client registrations, session
// records). A cache-tuned Redis — eviction enabled, no persistence — makes
// every "user consent required: no stored credential" incident look like an
// application bug when it is really the store shedding data.
//
// Best effort by design: managed offerings (GCP Memorystore) block CONFIG, so
// unreadable settings are skipped silently rather than reported as problems.
func WarnIfVolatile(ctx context.Context, rc *redis.Client, logger *slog.Logger) {
	if rc == nil || logger == nil {
		return
	}
	var policy, persistenceInfo, save string
	sawPersistence := false
	if vals, err := rc.ConfigGet(ctx, "maxmemory-policy").Result(); err == nil {
		policy = vals["maxmemory-policy"]
	}
	if info, err := rc.Info(ctx, "persistence").Result(); err == nil {
		persistenceInfo = info
		sawPersistence = true
	}
	if vals, err := rc.ConfigGet(ctx, "save").Result(); err == nil {
		save = vals["save"]
		sawPersistence = true
	}
	problems := volatilityProblems(policy, persistenceInfo, save, sawPersistence)
	if len(problems) == 0 {
		return
	}
	logger.Warn("mcp vault: the Redis backing durable OAuth state is volatile; "+
		"users will be sent back through consent whenever it drops data",
		slog.String("problems", strings.Join(problems, "; ")))
}

// volatilityProblems is the pure decision behind WarnIfVolatile, split out so
// the policy can be tested without a Redis that honours CONFIG.
func volatilityProblems(policy, persistenceInfo, save string, sawPersistence bool) []string {
	var problems []string
	if policy != "" && policy != "noeviction" {
		problems = append(problems, "maxmemory-policy="+policy+" can evict stored credentials under memory pressure (want noeviction)")
	}
	persistent := strings.Contains(persistenceInfo, "aof_enabled:1") || strings.TrimSpace(save) != ""
	if sawPersistence && !persistent {
		problems = append(problems, "no persistence configured (AOF off, RDB snapshots disabled): a restart wipes every stored credential")
	}
	return problems
}

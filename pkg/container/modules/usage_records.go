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
	"context"
	"log/slog"

	appusage "github.com/NeuralTrust/TrustGate/pkg/app/usage"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/container"
	usagedomain "github.com/NeuralTrust/TrustGate/pkg/domain/usage"
	"github.com/NeuralTrust/TrustGate/pkg/infra/bootlog"
	"github.com/NeuralTrust/TrustGate/pkg/infra/o11y"
	usageinfra "github.com/NeuralTrust/TrustGate/pkg/infra/telemetry/usage"
)

// UsageRecords provides the usage record emitter and the counter of its outcomes.
func UsageRecords(c *container.Container) error {
	for _, provider := range []any{
		func(cfg *config.Config, sdk *o11y.SDK) (usagedomain.OutcomeRecorder, error) {
			return o11y.NewUsageRecordsMetrics(cfg, sdk)
		},
		newUsageEmitter,
		func(e *usageinfra.Emitter) usagedomain.Emitter { return e },
		func(cfg *config.Config, e usagedomain.Emitter, outcomes usagedomain.OutcomeRecorder) appusage.RequestRecorder {
			return appusage.NewRequestRecorder(cfg.UsageRecords.Enabled, e, outcomes)
		},
	} {
		if err := c.Provide(provider); err != nil {
			return err
		}
	}
	return nil
}

func newUsageEmitter(
	cfg *config.Config,
	outcomes usagedomain.OutcomeRecorder,
	logger *slog.Logger,
) (*usageinfra.Emitter, error) {
	emitter, err := usageinfra.New(context.Background(), cfg, outcomes, logger)
	if err != nil {
		return nil, err
	}
	if emitter.Enabled() {
		logger.Info(bootlog.UsageRecordsEnabled, slog.Int("queue_size", cfg.UsageRecords.QueueSize))
	}
	return emitter, nil
}

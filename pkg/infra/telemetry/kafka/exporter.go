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

package kafka

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	appmetrics "github.com/NeuralTrust/TrustGate/pkg/app/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/events"
	infratelemetry "github.com/NeuralTrust/TrustGate/pkg/infra/telemetry"
	"github.com/NeuralTrust/TrustGate/pkg/metrics"
)

const ExporterName = "kafka"

type Exporter struct {
	infratelemetry.KafkaBase
}

func NewKafkaTemplate(logger *slog.Logger, kafkaCfg config.KafkaConfig) *Exporter {
	return &Exporter{
		KafkaBase: infratelemetry.NewKafkaBase(logger, kafkaCfg),
	}
}

func (p *Exporter) Name() string {
	return ExporterName
}

func (p *Exporter) DataClass() metrics.DataClass { return metrics.Metadata }

func (p *Exporter) ValidateConfig(settings map[string]interface{}) error {
	cfg, err := p.ResolveBaseConfig(settings)
	if err != nil {
		return err
	}
	if len(cfg.Brokers) == 0 {
		return errors.New("kafka: brokers are required")
	}
	if strings.TrimSpace(cfg.Topic) == "" {
		return errors.New("kafka: topic is required")
	}
	return nil
}

func (p *Exporter) WithSettings(settings map[string]interface{}) (appmetrics.Exporter, error) {
	cfg, err := p.ResolveBaseConfig(settings)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.Topic) == "" {
		return nil, errors.New("kafka: topic is required")
	}
	exporter := &Exporter{
		KafkaBase: infratelemetry.NewKafkaBase(p.Logger, p.EnvCfg),
	}
	if err := exporter.InitProducer(cfg); err != nil {
		return nil, err
	}
	return exporter, nil
}

func (p *Exporter) Publish(_ context.Context, evt *events.Event) error {
	if evt == nil {
		return nil
	}
	data, err := json.Marshal(evt)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}
	p.Logger.Debug("publishing event to kafka",
		slog.String("topic", p.Topic),
		slog.String("event", string(data)),
	)
	return p.Produce(data)
}

package kafka

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	apptelemetry "github.com/NeuralTrust/AgentGateway/pkg/app/telemetry"
	"github.com/NeuralTrust/AgentGateway/pkg/config"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/metrics/metric_events"
	infratelemetry "github.com/NeuralTrust/AgentGateway/pkg/infra/telemetry"
)

const ExporterName = "kafka"

var _ apptelemetry.Exporter = (*Exporter)(nil)

type Exporter struct {
	infratelemetry.KafkaBase
}

func NewKafkaExporter(logger *slog.Logger, kafkaCfg config.KafkaConfig) *Exporter {
	return &Exporter{
		KafkaBase: infratelemetry.NewKafkaBase(logger, kafkaCfg),
	}
}

func (p *Exporter) Name() string {
	return ExporterName
}

func (p *Exporter) ValidateConfig(settings map[string]interface{}) error {
	if err := p.ValidateBaseConfig(settings); err != nil {
		return err
	}
	cfg, _ := p.ResolveBaseConfig(settings)
	if cfg.Topic == "" {
		return fmt.Errorf("kafka topic is required")
	}
	return nil
}

func (p *Exporter) WithSettings(settings map[string]interface{}) (apptelemetry.Exporter, error) {
	cfg, err := p.ResolveBaseConfig(settings)
	if err != nil {
		return nil, err
	}

	exporter := &Exporter{
		KafkaBase: infratelemetry.NewKafkaBase(p.Logger, p.EnvCfg),
	}
	if err := exporter.InitProducer(cfg); err != nil {
		return nil, err
	}
	return exporter, nil
}

func (p *Exporter) Handle(_ context.Context, evt metric_events.Event) error {
	data, err := json.Marshal(evt)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}
	return p.Produce(data)
}

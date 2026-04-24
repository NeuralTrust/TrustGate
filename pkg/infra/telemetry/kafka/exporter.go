package kafka

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/metric_events"
	infraTelemetry "github.com/NeuralTrust/TrustGate/pkg/infra/telemetry"
	"github.com/sirupsen/logrus"
)

const (
	ExporterName = "kafka"
)

type Exporter struct {
	infraTelemetry.KafkaBase
}

func NewKafkaExporter(logger *logrus.Logger, kafkaCfg config.KafkaConfig) *Exporter {
	return &Exporter{
		KafkaBase: infraTelemetry.NewKafkaBase(logger, kafkaCfg),
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

func (p *Exporter) WithSettings(settings map[string]interface{}) (telemetry.Exporter, error) {
	cfg, err := p.ResolveBaseConfig(settings)
	if err != nil {
		return nil, err
	}

	exporter := &Exporter{
		KafkaBase: infraTelemetry.NewKafkaBase(p.Logger, p.EnvCfg),
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
	p.Logger.Debug(string(data))
	return p.Produce(data)
}

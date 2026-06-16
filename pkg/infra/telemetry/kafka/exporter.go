package kafka

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	appmetrics "github.com/NeuralTrust/AgentGateway/pkg/app/metrics"
	"github.com/NeuralTrust/AgentGateway/pkg/config"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/metrics/events"
	infratelemetry "github.com/NeuralTrust/AgentGateway/pkg/infra/telemetry"
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

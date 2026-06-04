package kafka

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/NeuralTrust/AgentGateway/pkg/config"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/metrics/events"
	infratelemetry "github.com/NeuralTrust/AgentGateway/pkg/infra/telemetry"
)

const ExporterName = "kafka"

type Exporter struct {
	infratelemetry.KafkaBase
}

func NewKafkaExporter(logger *slog.Logger, kafkaCfg config.KafkaConfig, topic string) (*Exporter, error) {
	exporter := &Exporter{
		KafkaBase: infratelemetry.NewKafkaBase(logger, kafkaCfg),
	}
	if err := exporter.InitProducer(infratelemetry.KafkaBaseConfig{
		Brokers: kafkaCfg.Brokers,
		Topic:   topic,
	}); err != nil {
		return nil, err
	}
	return exporter, nil
}

func (p *Exporter) Name() string {
	return ExporterName
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

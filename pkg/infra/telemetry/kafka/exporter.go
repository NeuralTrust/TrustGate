package kafka

import (
	"context"
	"errors"
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/mitchellh/mapstructure"
)

const (
	ExporterName = "kafka"
)

type Config struct {
	Host  string `mapstructure:"host"`
	Port  string `mapstructure:"port"`
	Topic string `mapstructure:"Topic"`
}

type Exporter struct {
	cfg Config
}

func NewKafkaExporter() *Exporter {
	return &Exporter{}
}

func (p *Exporter) Name() string {
	return ExporterName
}

func (p *Exporter) ValidateConfig() error {
	if p.cfg.Host == "" {
		return errors.New("kafka host is required")
	}
	if p.cfg.Port == "" {
		return errors.New("kafka port is required")
	}
	if p.cfg.Topic == "" {
		return errors.New("kafka topic is required")
	}
	return nil
}

func (p *Exporter) WithSettings(settings map[string]interface{}) (telemetry.Exporter, error) {
	var conf Config
	if err := mapstructure.Decode(settings, &conf); err != nil {
		return nil, fmt.Errorf("invalid kafka config: %w", err)
	}
	newProvider := &Exporter{
		cfg: conf,
	}

	if err := newProvider.ValidateConfig(); err != nil {
		return nil, err
	}
	return newProvider, nil
}

func (p *Exporter) Handle(ctx context.Context, evt *metrics.Event) error {
	return nil
}

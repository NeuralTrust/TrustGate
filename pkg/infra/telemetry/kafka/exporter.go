package kafka

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/metric_events"
	"github.com/confluentinc/confluent-kafka-go/kafka"
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
	cfg      Config
	producer *kafka.Producer
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
	producer, err := kafka.NewProducer(&kafka.ConfigMap{
		"bootstrap.servers": fmt.Sprintf("%s:%s", conf.Host, conf.Port),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create kafka producer: %w", err)
	}
	newProvider := &Exporter{
		cfg:      conf,
		producer: producer,
	}

	if err := newProvider.ValidateConfig(); err != nil {
		return nil, err
	}
	return newProvider, nil
}

func (p *Exporter) Handle(ctx context.Context, evt *metric_events.Event) error {
	if p.producer == nil {
		return errors.New("kafka producer is not initialized")
	}
	data, err := json.Marshal(evt)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}
	deliveryChan := make(chan kafka.Event)
	fmt.Println(string(data))
	err = p.producer.Produce(&kafka.Message{
		TopicPartition: kafka.TopicPartition{Topic: &p.cfg.Topic, Partition: kafka.PartitionAny},
		Value:          data,
	}, deliveryChan)
	if err != nil {
		return fmt.Errorf("failed to produce message: %w", err)
	}
	e := <-deliveryChan
	m := e.(*kafka.Message)

	if m.TopicPartition.Error != nil {
		return fmt.Errorf("delivery failed: %w", m.TopicPartition.Error)
	}

	close(deliveryChan)
	return nil
}

func (p *Exporter) Close() {
	if p.producer != nil {
		p.producer.Flush(5000)
		p.producer.Close()
	}
}

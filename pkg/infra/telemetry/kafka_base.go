package telemetry

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/confluentinc/confluent-kafka-go/kafka"
	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"
)

type KafkaBaseConfig struct {
	Host  string `mapstructure:"host"`
	Port  string `mapstructure:"port"`
	Topic string `mapstructure:"topic"`
}

type KafkaBase struct {
	EnvCfg   config.KafkaConfig
	Logger   *logrus.Logger
	Producer *kafka.Producer
	Topic    string
}

func NewKafkaBase(logger *logrus.Logger, envCfg config.KafkaConfig) KafkaBase {
	return KafkaBase{
		Logger: logger,
		EnvCfg: envCfg,
	}
}

func (b *KafkaBase) ResolveBaseConfig(settings map[string]interface{}) (KafkaBaseConfig, error) {
	var cfg KafkaBaseConfig
	if err := mapstructure.Decode(settings, &cfg); err != nil {
		return cfg, fmt.Errorf("invalid kafka config: %w", err)
	}
	if cfg.Host == "" {
		cfg.Host = b.EnvCfg.Host
	}
	if cfg.Port == "" {
		cfg.Port = b.EnvCfg.Port
	}
	return cfg, nil
}

func (b *KafkaBase) ValidateBaseConfig(settings map[string]interface{}) error {
	cfg, err := b.ResolveBaseConfig(settings)
	if err != nil {
		return err
	}
	if cfg.Host == "" {
		return errors.New("kafka host is required")
	}
	if cfg.Port == "" {
		return errors.New("kafka port is required")
	}
	return nil
}

func (b *KafkaBase) InitProducer(cfg KafkaBaseConfig) error {
	producer, err := kafka.NewProducer(&kafka.ConfigMap{
		"bootstrap.servers": fmt.Sprintf("%s:%s", cfg.Host, cfg.Port),
	})
	if err != nil {
		return fmt.Errorf("failed to create kafka producer: %w", err)
	}
	b.Producer = producer
	b.Topic = cfg.Topic

	if err := b.createTopicIfNotExists(cfg.Topic); err != nil {
		producer.Close()
		b.Producer = nil
		return fmt.Errorf("failed to ensure topic exists: %w", err)
	}
	return nil
}

func (b *KafkaBase) Produce(data []byte) error {
	if b.Producer == nil {
		return errors.New("kafka producer is not initialized")
	}
	deliveryChan := make(chan kafka.Event)
	err := b.Producer.Produce(&kafka.Message{
		TopicPartition: kafka.TopicPartition{Topic: &b.Topic, Partition: kafka.PartitionAny},
		Value:          data,
	}, deliveryChan)
	if err != nil {
		return fmt.Errorf("failed to produce message: %w", err)
	}
	e := <-deliveryChan
	m, ok := e.(*kafka.Message)
	if !ok {
		return errors.New("unexpected kafka event type on delivery channel")
	}
	if m.TopicPartition.Error != nil {
		return fmt.Errorf("delivery failed: %w", m.TopicPartition.Error)
	}
	close(deliveryChan)
	return nil
}

func (b *KafkaBase) Close() {
	if b.Producer != nil {
		b.Producer.Flush(5000)
		b.Producer.Close()
	}
}

func (b *KafkaBase) createTopicIfNotExists(topic string) error {
	b.Logger.WithField("topic", topic).Info("attempting to create kafka topic")
	adminClient, err := kafka.NewAdminClientFromProducer(b.Producer)
	if err != nil {
		return fmt.Errorf("failed to create kafka admin client: %w", err)
	}
	defer adminClient.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	topicSpec := []kafka.TopicSpecification{
		{
			Topic:             topic,
			NumPartitions:     3,
			ReplicationFactor: 1,
		},
	}
	results, err := adminClient.CreateTopics(ctx, topicSpec)
	if err != nil {
		return fmt.Errorf("failed to create topic: %w", err)
	}

	for _, result := range results {
		if result.Error.Code() != kafka.ErrNoError && result.Error.Code() != kafka.ErrTopicAlreadyExists {
			return fmt.Errorf("failed to create topic %s: %w", result.Topic, result.Error)
		}
	}
	b.Logger.WithField("topic", topic).Info("kafka topic ready")
	return nil
}

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

package telemetry

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/NeuralTrust/AgentGateway/pkg/config"
	"github.com/confluentinc/confluent-kafka-go/kafka"
	"github.com/mitchellh/mapstructure"
)

const (
	topicNumPartitions     = 3
	topicReplicationFactor = 1
	topicCreateTimeout     = 30 * time.Second
	producerFlushTimeoutMs = 5000
)

type KafkaBaseConfig struct {
	Brokers []string `mapstructure:"brokers"`
	Topic   string   `mapstructure:"topic"`
}

type KafkaBase struct {
	EnvCfg   config.KafkaConfig
	Logger   *slog.Logger
	Producer *kafka.Producer
	Topic    string
}

func NewKafkaBase(logger *slog.Logger, envCfg config.KafkaConfig) KafkaBase {
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
	if len(cfg.Brokers) == 0 {
		cfg.Brokers = b.EnvCfg.Brokers
	}
	return cfg, nil
}

func (b *KafkaBase) ValidateBaseConfig(settings map[string]interface{}) error {
	cfg, err := b.ResolveBaseConfig(settings)
	if err != nil {
		return err
	}
	if len(cfg.Brokers) == 0 {
		return errors.New("kafka brokers are required")
	}
	return nil
}

// InitProducer creates the producer and starts the asynchronous delivery-report
// handler. Topic creation runs in the background so an unreachable broker never
// blocks startup.
func (b *KafkaBase) InitProducer(cfg KafkaBaseConfig) error {
	producer, err := kafka.NewProducer(&kafka.ConfigMap{
		"bootstrap.servers": strings.Join(cfg.Brokers, ","),
	})
	if err != nil {
		return fmt.Errorf("failed to create kafka producer: %w", err)
	}
	b.Producer = producer
	b.Topic = cfg.Topic

	go b.handleDeliveryReports()
	go b.ensureTopic(cfg.Topic)

	return nil
}

// Produce enqueues a message without blocking on delivery. Delivery outcomes are
// reported asynchronously through handleDeliveryReports.
func (b *KafkaBase) Produce(data []byte) error {
	if b.Producer == nil {
		return errors.New("kafka producer is not initialized")
	}
	return b.Producer.Produce(&kafka.Message{
		TopicPartition: kafka.TopicPartition{Topic: &b.Topic, Partition: kafka.PartitionAny},
		Value:          data,
	}, nil)
}

func (b *KafkaBase) Close() {
	if b.Producer == nil {
		return
	}
	if remaining := b.Producer.Flush(producerFlushTimeoutMs); remaining > 0 {
		b.Logger.Warn("kafka producer closed with undelivered messages",
			slog.String("topic", b.Topic),
			slog.Int("remaining", remaining),
		)
	}
	b.Producer.Close()
}

// handleDeliveryReports drains the producer event channel, logging failed
// deliveries and client errors. It exits when the producer is closed.
func (b *KafkaBase) handleDeliveryReports() {
	for e := range b.Producer.Events() {
		switch ev := e.(type) {
		case *kafka.Message:
			if ev.TopicPartition.Error != nil {
				b.Logger.Error("kafka delivery failed",
					slog.String("topic", b.Topic),
					slog.String("error", ev.TopicPartition.Error.Error()),
				)
			}
		case kafka.Error:
			b.Logger.Error("kafka client error", slog.String("error", ev.Error()))
		}
	}
}

func (b *KafkaBase) ensureTopic(topic string) {
	if topic == "" {
		return
	}
	b.Logger.Info("ensuring kafka topic exists", slog.String("topic", topic))
	adminClient, err := kafka.NewAdminClientFromProducer(b.Producer)
	if err != nil {
		b.Logger.Error("failed to create kafka admin client", slog.String("error", err.Error()))
		return
	}
	defer adminClient.Close()

	ctx, cancel := context.WithTimeout(context.Background(), topicCreateTimeout)
	defer cancel()

	results, err := adminClient.CreateTopics(ctx, []kafka.TopicSpecification{
		{
			Topic:             topic,
			NumPartitions:     topicNumPartitions,
			ReplicationFactor: topicReplicationFactor,
		},
	})
	if err != nil {
		b.Logger.Error("failed to create kafka topic",
			slog.String("topic", topic),
			slog.String("error", err.Error()),
		)
		return
	}

	for _, result := range results {
		if result.Error.Code() != kafka.ErrNoError && result.Error.Code() != kafka.ErrTopicAlreadyExists {
			b.Logger.Error("failed to create kafka topic",
				slog.String("topic", result.Topic),
				slog.String("error", result.Error.String()),
			)
			return
		}
	}
	b.Logger.Info("kafka topic ready", slog.String("topic", topic))
}

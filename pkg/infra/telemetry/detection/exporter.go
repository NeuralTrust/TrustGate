package detection

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/metric_events"
	pluginTypes "github.com/NeuralTrust/TrustGate/pkg/infra/plugins/types"
	eventsv1 "github.com/NeuralTrust/event-schemas/gen/go/events/v1"
	"github.com/confluentinc/confluent-kafka-go/kafka"
	"github.com/google/uuid"
	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	ExporterName = "detector"
	DefaultTopic = "detections"
	ServiceName  = "trustgate"
)

type Config struct {
	Host  string `mapstructure:"host"`
	Port  string `mapstructure:"port"`
	Topic string `mapstructure:"topic"`
}

type Exporter struct {
	cfg      Config
	producer *kafka.Producer
	logger   *logrus.Logger
}

func NewDetectionExporter(logger *logrus.Logger) *Exporter {
	return &Exporter{
		logger: logger,
	}
}

func (p *Exporter) Name() string {
	return ExporterName
}

func (p *Exporter) ValidateConfig(settings map[string]interface{}) error {
	var conf Config
	if err := mapstructure.Decode(settings, &conf); err != nil {
		return fmt.Errorf("invalid detection config: %w", err)
	}
	if conf.Host == "" {
		return errors.New("detection kafka host is required")
	}
	if conf.Port == "" {
		return errors.New("detection kafka port is required")
	}
	return nil
}

func (p *Exporter) WithSettings(settings map[string]interface{}) (telemetry.Exporter, error) {
	var conf Config
	if err := mapstructure.Decode(settings, &conf); err != nil {
		return nil, fmt.Errorf("invalid detection config: %w", err)
	}
	if conf.Topic == "" {
		conf.Topic = DefaultTopic
	}
	producer, err := kafka.NewProducer(&kafka.ConfigMap{
		"bootstrap.servers": fmt.Sprintf("%s:%s", conf.Host, conf.Port),
	})
	if err != nil {
		p.logger.WithError(err).WithFields(logrus.Fields{
			"host": conf.Host,
			"port": conf.Port,
		}).Error("cannot connect with kafka (detection)")
		return nil, fmt.Errorf("failed to create kafka producer: %w", err)
	}
	exporter := &Exporter{
		cfg:      conf,
		producer: producer,
		logger:   p.logger,
	}
	if err := exporter.createTopicIfNotExists(conf.Topic); err != nil {
		producer.Close()
		return nil, fmt.Errorf("failed to ensure topic exists: %w", err)
	}
	return exporter, nil
}

func (p *Exporter) Handle(_ context.Context, evt metric_events.Event) error {
	if !p.shouldExport(evt) {
		return nil
	}
	if p.producer == nil {
		return errors.New("detection kafka producer is not initialized")
	}

	detectionEvt := p.toDetectionEvent(evt)
	data, err := json.Marshal(detectionEvt)
	if err != nil {
		return fmt.Errorf("failed to marshal detection event: %w", err)
	}

	deliveryChan := make(chan kafka.Event)
	err = p.producer.Produce(&kafka.Message{
		TopicPartition: kafka.TopicPartition{Topic: &p.cfg.Topic, Partition: kafka.PartitionAny},
		Value:          data,
	}, deliveryChan)
	if err != nil {
		return fmt.Errorf("failed to produce message (detection): %w", err)
	}
	e := <-deliveryChan
	m, ok := e.(*kafka.Message)
	if !ok {
		return fmt.Errorf("failed to cast message (detection): %w", err)
	}
	if m.TopicPartition.Error != nil {
		return fmt.Errorf("delivery failed (detection): %w", m.TopicPartition.Error)
	}
	close(deliveryChan)
	return nil
}

func (p *Exporter) toDetectionEvent(evt metric_events.Event) *eventsv1.DetectionEvent {
	detEvt := &eventsv1.DetectionEvent{
		EventId:     uuid.New().String(),
		ServiceName: ServiceName,
		TeamId:      evt.TeamID,
		GatewayId:   evt.GatewayID,
		EngineId:    evt.EngineID,
		TraceId:     evt.TraceID,
		Type:        evt.Type,
		UserIp:      evt.IP,
		Latency:     evt.Latency,
		OccurredOn:  timestamppb.Now(),
	}

	detEvt.EnginePolicyId = evt.PolicyID
	detEvt.GatewayRuleId = evt.RuleID

	if evt.Plugin != nil {
		detEvt.Action = evt.Plugin.Decision
		detEvt.Latency = evt.Plugin.Latency

		if evt.Plugin.Extras != nil {
			if extras, err := toStruct(evt.Plugin.Extras); err == nil {
				detEvt.Metadata = extras
			}
		}
	}

	return detEvt
}

func toStruct(v interface{}) (*structpb.Struct, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	s := &structpb.Struct{}
	if err := s.UnmarshalJSON(data); err != nil {
		return nil, err
	}
	return s, nil
}

func (p *Exporter) shouldExport(evt metric_events.Event) bool {
	if evt.StatusCode == 403 {
		return true
	}
	if evt.Plugin != nil {
		decision := pluginTypes.Decision(evt.Plugin.Decision)
		if decision == pluginTypes.DecisionBlock ||
			decision == pluginTypes.DecisionThrottle ||
			decision == pluginTypes.DecisionMasked {
			return true
		}
	}
	return false
}

func (p *Exporter) Close() {
	if p.producer != nil {
		p.producer.Flush(5000)
		p.producer.Close()
	}
}

func (p *Exporter) createTopicIfNotExists(topic string) error {
	p.logger.WithField("topic", topic).Info("attempting to create detection topic")
	adminClient, err := kafka.NewAdminClientFromProducer(p.producer)
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
	p.logger.WithField("topic", topic).Info("detection topic ready")
	return nil
}

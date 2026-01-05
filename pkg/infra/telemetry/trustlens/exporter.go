package trustlens

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/metric_events"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/confluentinc/confluent-kafka-go/kafka"
	"github.com/gofiber/fiber/v2/log"
	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"
)

const (
	ExporterName = "trustlens"
)

type Config struct {
	Host    string  `mapstructure:"host"`
	Port    string  `mapstructure:"port"`
	Topic   string  `mapstructure:"Topic"`
	Mapping Mapping `mapstructure:"mapping"`
}

type Mapping struct {
	Input  DataMapping `mapstructure:"input"`
	Output DataMapping `mapstructure:"output"`
}

type DataMapping struct {
	ExtractFields  map[string]string `mapstructure:"extract_fields"`
	DataProjection map[string]string `mapstructure:"data_projection"`
}

type Exporter struct {
	cfg      Config
	producer *kafka.Producer
	logger   *logrus.Logger
}

func NewTrustLensExporter(logger *logrus.Logger) *Exporter {
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
		return fmt.Errorf("invalid kafka config: %w", err)
	}
	if conf.Host == "" {
		return errors.New("kafka host is required")
	}
	if conf.Port == "" {
		return errors.New("kafka port is required")
	}
	if conf.Topic == "" {
		return errors.New("kafka topic is required")
	}
	return nil
}

func (p *Exporter) WithSettings(settings map[string]interface{}) (telemetry.Exporter, error) {
	var conf Config
	if err := mapstructure.Decode(settings, &conf); err != nil {
		return nil, fmt.Errorf("invalid kafka (trustlens) config: %w", err)
	}
	producer, err := kafka.NewProducer(&kafka.ConfigMap{
		"bootstrap.servers": fmt.Sprintf("%s:%s", conf.Host, conf.Port),
	})
	if err != nil {
		p.logger.Error("cannot connect with kafka (trustlens): ", err, " ", conf.Host, " ", conf.Port, " ", conf.Topic, "")
		return nil, fmt.Errorf("failed to create kafka producer: %w", err)
	}
	exporter := &Exporter{
		cfg:      conf,
		producer: producer,
		logger:   p.logger,
	}
	p.logger.Error("trying to create topic: ", conf.Topic, "")
	if err := exporter.createTopicIfNotExists(conf.Topic); err != nil {
		producer.Close()
		return nil, fmt.Errorf("failed to ensure topic exists: %w", err)
	}
	return exporter, nil
}

func (p *Exporter) Handle(ctx context.Context, evt metric_events.Event) error {
	if p.producer == nil {
		return errors.New("kafka (trustlens) producer is not initialized")
	}
	if evt.IsTypePlugin() {
		return nil
	}

	if rule, ok := ctx.Value(string(common.MatchedRuleContextKey)).(*types.ForwardingRuleDTO); ok {
		if rule.TrustLens == nil {
			return nil
		}
		if rule.TrustLens != nil && rule.TrustLens.Mapping != nil {
			p.cfg.Mapping = Mapping{
				Input: DataMapping{
					ExtractFields:  rule.TrustLens.Mapping.Input.ExtractFields,
					DataProjection: rule.TrustLens.Mapping.Input.DataProjection,
				},
				Output: DataMapping{
					ExtractFields:  rule.TrustLens.Mapping.Output.ExtractFields,
					DataProjection: rule.TrustLens.Mapping.Output.DataProjection,
				},
			}
		}
	}

	if evt.LastStreamLine != nil {
		if p.isValidJSON(evt.LastStreamLine) {
			evt.Output = string(evt.LastStreamLine)
		}
	}
	// Apply mapping transformations to the event and get extracted fields
	extractedFields, err := p.applyMappingTransformations(&evt)
	if err != nil {
		return fmt.Errorf("failed to apply mapping transformations: %w", err)
	}

	// Convert event to map
	eventMap := make(map[string]interface{})
	eventBytes, err := json.Marshal(evt)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	if err := json.Unmarshal(eventBytes, &eventMap); err != nil {
		return fmt.Errorf("failed to unmarshal event: %w", err)
	}

	for field, value := range extractedFields {
		eventMap[field] = value
	}

	data, err := json.Marshal(eventMap)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}
	p.logger.Debug(string(data))
	deliveryChan := make(chan kafka.Event)
	err = p.producer.Produce(&kafka.Message{
		TopicPartition: kafka.TopicPartition{Topic: &p.cfg.Topic, Partition: kafka.PartitionAny},
		Value:          data,
	}, deliveryChan)
	if err != nil {
		return fmt.Errorf("failed to produce message (trustlens): %w", err)
	}
	e := <-deliveryChan
	m, ok := e.(*kafka.Message)
	if !ok {
		return fmt.Errorf("failed to cast message (trustlens): %w", err)
	}

	if m.TopicPartition.Error != nil {
		return fmt.Errorf("delivery failed (trustlens): %w", m.TopicPartition.Error)
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

func (p *Exporter) isValidJSON(data []byte) bool {
	var js interface{}
	return json.Unmarshal(data, &js) == nil
}

func (p *Exporter) applyMappingTransformations(evt *metric_events.Event) (map[string]interface{}, error) {
	extractedFields := make(map[string]interface{})

	if len(p.cfg.Mapping.Input.ExtractFields) > 0 || len(p.cfg.Mapping.Input.DataProjection) > 0 {
		fields, err := p.applyMapping(evt, true)
		if err != nil {
			return nil, fmt.Errorf("failed to apply input mapping: %w", err)
		}
		for k, v := range fields {
			extractedFields[k] = v
		}
	}
	if len(p.cfg.Mapping.Output.ExtractFields) > 0 || len(p.cfg.Mapping.Output.DataProjection) > 0 {
		fields, err := p.applyMapping(evt, false)
		if err != nil {
			return nil, fmt.Errorf("failed to apply output mapping: %w", err)
		}
		for k, v := range fields {
			extractedFields[k] = v
		}
	}
	return extractedFields, nil
}

func (p *Exporter) applyMapping(evt *metric_events.Event, isInput bool) (map[string]interface{}, error) {
	var (
		jsonData  string
		mapping   DataMapping
		fieldName string
	)

	if isInput {
		jsonData = evt.Input
		mapping = p.cfg.Mapping.Input
		fieldName = "input"
	} else {
		jsonData = evt.Output
		mapping = p.cfg.Mapping.Output
		fieldName = "output"
	}

	if jsonData == "" {
		return nil, nil
	}

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(jsonData), &data); err != nil {
		log.Warn("failed to unmarshal data: ", err, " ", jsonData, " ", isInput, " ", fieldName, " ")
		return nil, nil
	}

	extractedFields := make(map[string]interface{})
	if len(mapping.ExtractFields) > 0 {
		for eventField, dataField := range mapping.ExtractFields {
			if value, ok := data[dataField]; ok {
				extractedFields[eventField] = value
			}
		}
	}

	if len(mapping.DataProjection) > 0 {
		for targetField, sourceField := range mapping.DataProjection {
			var concatenatedValues string
			if value, ok := data[sourceField]; ok {
				switch v := value.(type) {
				case string:
					concatenatedValues = v
				default:
					valueJSON, err := json.Marshal(v)
					if err == nil {
						concatenatedValues = string(valueJSON)
					}
				}
			}

			// Set the value to the appropriate field in the event
			switch targetField {
			case "input":
				evt.Input = concatenatedValues
			case "output":
				evt.Output = concatenatedValues
			case "feedback_tag":
				evt.FeedBackTag = concatenatedValues
			case "feedback_text":
				evt.FeedBackText = concatenatedValues
			}
		}
	} else {
		transformedJSON, err := json.Marshal(data)
		if err != nil {
			return extractedFields, fmt.Errorf("failed to marshal transformed %s: %w", fieldName, err)
		}

		// If no data projection is specified, use the default behavior based on isInput
		if isInput {
			evt.Input = string(transformedJSON)
		} else {
			evt.Output = string(transformedJSON)
		}
	}

	return extractedFields, nil
}

func (p *Exporter) createTopicIfNotExists(topic string) error {
	fmt.Println("attempting to create topic: " + topic)
	adminClient, err := kafka.NewAdminClientFromProducer(p.producer)
	if err != nil {
		fmt.Println("cannot create kafka admin client")
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
			fmt.Println("create topic error: ", result.Error.Code(), result.Error.String(), " ", result.Topic, "")
			return fmt.Errorf("failed to create topic %s: %w", result.Topic, result.Error)
		}
	}
	fmt.Println("create topic result: ", results)
	p.cfg.Topic = topic
	return nil
}

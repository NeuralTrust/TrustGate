package trustlens

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/metric_events"
	infraTelemetry "github.com/NeuralTrust/TrustGate/pkg/infra/telemetry"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/gofiber/fiber/v2/log"
	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"
)

const (
	ExporterName = "trustlens"
	DefaultTopic = "metrics"
)

type Config struct {
	infraTelemetry.KafkaBaseConfig `mapstructure:",squash"`
	Mapping                        Mapping `mapstructure:"mapping"`
}

type Mapping struct {
	Input  DataMapping `mapstructure:"input"`
	Output DataMapping `mapstructure:"output"`
}

type DataMapping struct {
	ExtractFields map[string]string `mapstructure:"extract_fields"`
}

type Exporter struct {
	infraTelemetry.KafkaBase
	mapping Mapping
}

func NewTrustLensExporter(logger *logrus.Logger, kafkaCfg config.KafkaConfig) *Exporter {
	return &Exporter{
		KafkaBase: infraTelemetry.NewKafkaBase(logger, kafkaCfg),
	}
}

func (p *Exporter) Name() string {
	return ExporterName
}

func (p *Exporter) ValidateConfig(settings map[string]interface{}) error {
	return p.ValidateBaseConfig(settings)
}

func (p *Exporter) WithSettings(settings map[string]interface{}) (telemetry.Exporter, error) {
	var conf Config
	if err := mapstructure.Decode(settings, &conf); err != nil {
		return nil, fmt.Errorf("invalid kafka (trustlens) config: %w", err)
	}

	baseCfg, err := p.ResolveBaseConfig(settings)
	if err != nil {
		return nil, err
	}
	if baseCfg.Topic == "" {
		baseCfg.Topic = DefaultTopic
	}

	exporter := &Exporter{
		KafkaBase: infraTelemetry.NewKafkaBase(p.Logger, p.EnvCfg),
		mapping:   conf.Mapping,
	}
	if err := exporter.InitProducer(baseCfg); err != nil {
		return nil, err
	}
	return exporter, nil
}

func (p *Exporter) Handle(ctx context.Context, evt metric_events.Event) error {
	if rule, ok := ctx.Value(string(common.MatchedRuleContextKey)).(*types.ForwardingRuleDTO); ok {
		if rule.TrustLens == nil {
			return nil
		}
		p.mapping = p.buildMappingWithDefaults(rule.TrustLens.Mapping)
	}

	extractedFields, err := p.applyMappingTransformations(&evt)
	if err != nil {
		return fmt.Errorf("failed to apply mapping transformations: %w", err)
	}

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
	p.Logger.Debug(string(data))
	return p.Produce(data)
}

func (p *Exporter) applyMappingTransformations(evt *metric_events.Event) (map[string]interface{}, error) {
	extractedFields := make(map[string]interface{})

	if len(p.mapping.Input.ExtractFields) > 0 {
		fields, err := p.applyMapping(evt, true)
		if err != nil {
			return nil, fmt.Errorf("failed to apply input mapping: %w", err)
		}
		for k, v := range fields {
			extractedFields[k] = v
		}
	}
	if len(p.mapping.Output.ExtractFields) > 0 {
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
		mapping = p.mapping.Input
		fieldName = "input"
	} else {
		jsonData = evt.Output
		mapping = p.mapping.Output
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

	transformedJSON, err := json.Marshal(data)
	if err != nil {
		return extractedFields, fmt.Errorf("failed to marshal transformed %s: %w", fieldName, err)
	}

	if isInput {
		evt.Input = string(transformedJSON)
	} else {
		evt.Output = string(transformedJSON)
	}

	return extractedFields, nil
}

func (p *Exporter) buildMappingWithDefaults(ruleMapping *types.TrustLensMappingDTO) Mapping {
	defaultExtractFields := map[string]string{
		"user_id":         "user_id",
		"conversation_id": "conversation_id",
	}

	if ruleMapping == nil {
		return Mapping{
			Input: DataMapping{
				ExtractFields: defaultExtractFields,
			},
		}
	}

	inputExtractFields := make(map[string]string)
	for k, v := range defaultExtractFields {
		inputExtractFields[k] = v
	}
	for k, v := range ruleMapping.Input.ExtractFields {
		inputExtractFields[k] = v
	}

	return Mapping{
		Input: DataMapping{
			ExtractFields: inputExtractFields,
		},
		Output: DataMapping{
			ExtractFields: ruleMapping.Output.ExtractFields,
		},
	}
}

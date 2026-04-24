package detection

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/metric_events"
	pluginTypes "github.com/NeuralTrust/TrustGate/pkg/infra/plugins/types"
	infraTelemetry "github.com/NeuralTrust/TrustGate/pkg/infra/telemetry"
	eventsv1 "github.com/NeuralTrust/event-schemas/gen/go/events/v1"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	ExporterName = "detector"
	DefaultTopic = "detections"
	ServiceName  = "trustgate"
)

type Exporter struct {
	infraTelemetry.KafkaBase
}

func NewDetectionExporter(logger *logrus.Logger, kafkaCfg config.KafkaConfig) *Exporter {
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
	cfg, err := p.ResolveBaseConfig(settings)
	if err != nil {
		return nil, err
	}
	if cfg.Topic == "" {
		cfg.Topic = DefaultTopic
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
	if !p.shouldExport(evt) {
		return nil
	}

	detectionEvt := p.toDetectionEvent(evt)
	data, err := json.Marshal(detectionEvt)
	if err != nil {
		return fmt.Errorf("failed to marshal detection event: %w", err)
	}
	return p.Produce(data)
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

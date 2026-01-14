package metrics

import "github.com/NeuralTrust/TrustGate/pkg/infra/metrics/metric_events"

type EmbeddedParam struct {
	Key   string
	Value string
}

type collectorOptions struct {
	traceID        string
	embeddedParams []EmbeddedParam
}

type Option func(*collectorOptions)

func WithTraceID(traceID string) Option {
	return func(o *collectorOptions) {
		o.traceID = traceID
	}
}

// WithEmbeddedParam adds a parameter to be embedded in the metrics events.
func WithEmbeddedParam(key, value string) Option {
	return func(o *collectorOptions) {
		o.embeddedParams = append(o.embeddedParams, EmbeddedParam{Key: key, Value: value})
	}
}

func applyEmbeddedParam(evt *metric_events.Event, ep EmbeddedParam) {
	switch ep.Key {
	case "rule_id":
		evt.RuleID = ep.Value
	case "policy_id":
		evt.PolicyID = ep.Value
	}
}

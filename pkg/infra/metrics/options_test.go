package metrics

import (
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/metric_events"
	"github.com/stretchr/testify/assert"
)

func TestWithTraceID(t *testing.T) {
	traceID := "test-trace-id"
	collector := NewCollector(&Config{
		EnablePluginTraces:  true,
		EnableRequestTraces: true,
	}, WithTraceID(traceID))

	assert.Equal(t, traceID, collector.traceID)
}

func TestWithTraceID_Empty(t *testing.T) {
	collector := NewCollector(&Config{
		EnablePluginTraces:  true,
		EnableRequestTraces: true,
	})

	assert.NotEmpty(t, collector.traceID)
}

func TestWithEmbeddedParam_RuleID(t *testing.T) {
	ruleID := "rule-123"
	collector := NewCollector(&Config{
		EnablePluginTraces:  true,
		EnableRequestTraces: true,
	}, WithEmbeddedParam("rule_id", ruleID))

	evt := metric_events.NewPluginEvent()
	collector.Emit(evt)

	events := collector.GetEvents()
	assert.Len(t, events, 1)
	assert.Equal(t, ruleID, events[0].RuleID)
}

func TestWithEmbeddedParam_PolicyID(t *testing.T) {
	policyID := "policy-456"
	collector := NewCollector(&Config{
		EnablePluginTraces:  true,
		EnableRequestTraces: true,
	}, WithEmbeddedParam("policy_id", policyID))

	evt := metric_events.NewPluginEvent()
	collector.Emit(evt)

	events := collector.GetEvents()
	assert.Len(t, events, 1)
	assert.Equal(t, policyID, events[0].PolicyID)
}

func TestWithEmbeddedParam_Multiple(t *testing.T) {
	ruleID := "rule-123"
	policyID := "policy-456"
	collector := NewCollector(&Config{
		EnablePluginTraces:  true,
		EnableRequestTraces: true,
	},
		WithEmbeddedParam("rule_id", ruleID),
		WithEmbeddedParam("policy_id", policyID),
	)

	evt := metric_events.NewPluginEvent()
	collector.Emit(evt)

	events := collector.GetEvents()
	assert.Len(t, events, 1)
	assert.Equal(t, ruleID, events[0].RuleID)
	assert.Equal(t, policyID, events[0].PolicyID)
}

func TestWithEmbeddedParam_UnknownKey(t *testing.T) {
	collector := NewCollector(&Config{
		EnablePluginTraces:  true,
		EnableRequestTraces: true,
	}, WithEmbeddedParam("unknown_key", "value"))

	evt := metric_events.NewPluginEvent()
	collector.Emit(evt)

	events := collector.GetEvents()
	assert.Len(t, events, 1)
	// Unknown keys should not cause errors, just be ignored
	assert.Empty(t, events[0].RuleID)
	assert.Empty(t, events[0].PolicyID)
}

func TestAddEmbeddedParam(t *testing.T) {
	collector := NewCollector(&Config{
		EnablePluginTraces:  true,
		EnableRequestTraces: true,
	})

	collector.AddEmbeddedParam(EmbeddedParam{Key: "policy_id", Value: "policy-789"})

	evt := metric_events.NewPluginEvent()
	collector.Emit(evt)

	events := collector.GetEvents()
	assert.Len(t, events, 1)
	assert.Equal(t, "policy-789", events[0].PolicyID)
}

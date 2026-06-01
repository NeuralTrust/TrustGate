package metrics_test

import (
	"testing"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/metrics"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/metrics/metric_events"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCollector_EmitAndFlush(t *testing.T) {
	c := metrics.NewCollector(&metrics.Config{EnableRequestTraces: true}, metrics.WithTraceID("trace-1"))

	c.Emit(metric_events.NewTraceEvent())
	c.Emit(metric_events.NewTraceEvent())

	events := c.Flush()
	require.Len(t, events, 2)
	assert.Equal(t, "trace-1", events[0].TraceID)

	assert.Empty(t, c.Flush(), "flush should drain the buffer")
}

func TestCollector_EmitGatesByConfig(t *testing.T) {
	t.Run("trace events dropped when request traces disabled", func(t *testing.T) {
		c := metrics.NewCollector(&metrics.Config{EnableRequestTraces: false})
		c.Emit(metric_events.NewTraceEvent())
		assert.Empty(t, c.GetEvents())
	})

	t.Run("plugin events dropped when plugin traces disabled", func(t *testing.T) {
		c := metrics.NewCollector(&metrics.Config{EnablePluginTraces: false})
		c.Emit(metric_events.NewPluginEvent())
		assert.Empty(t, c.GetEvents())
	})

	t.Run("plugin events kept when plugin traces enabled", func(t *testing.T) {
		c := metrics.NewCollector(&metrics.Config{EnablePluginTraces: true})
		c.Emit(metric_events.NewPluginEvent())
		assert.Len(t, c.GetEvents(), 1)
	})
}

func TestCollector_EmbeddedParams(t *testing.T) {
	c := metrics.NewCollector(
		&metrics.Config{EnableRequestTraces: true},
		metrics.WithEmbeddedParam("rule_id", "r-1"),
		metrics.WithEmbeddedParam("policy_id", "p-1"),
	)
	c.Emit(metric_events.NewTraceEvent())

	events := c.GetEvents()
	require.Len(t, events, 1)
	assert.Equal(t, "r-1", events[0].RuleID)
	assert.Equal(t, "p-1", events[0].PolicyID)
}

func TestCollector_NilConfigIsNoop(t *testing.T) {
	c := metrics.NewCollector(nil)
	c.Emit(metric_events.NewTraceEvent())
	assert.Empty(t, c.GetEvents())
}

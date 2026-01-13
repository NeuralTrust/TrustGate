package metrics

import (
	"testing"

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

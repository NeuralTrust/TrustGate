package telemetry

import (
	"context"
	"errors"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/metric_events"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/stretchr/testify/assert"
)

// mockExporter is a test mock for telemetry.Exporter
type mockExporter struct {
	name              string
	validateErr       error
	withSettingsErr   error
	withSettingsExporter telemetry.Exporter
}

func newMockExporter(name string) *mockExporter {
	return &mockExporter{name: name}
}

func (m *mockExporter) Name() string {
	return m.name
}

func (m *mockExporter) ValidateConfig(settings map[string]interface{}) error {
	return m.validateErr
}

func (m *mockExporter) Handle(ctx context.Context, evt metric_events.Event) error {
	return nil
}

func (m *mockExporter) WithSettings(settings map[string]interface{}) (telemetry.Exporter, error) {
	if m.withSettingsErr != nil {
		return nil, m.withSettingsErr
	}
	if m.withSettingsExporter != nil {
		return m.withSettingsExporter, nil
	}
	return m, nil
}

func (m *mockExporter) Close() {}

func TestNewProviderLocator_NoOptions(t *testing.T) {
	locator := NewProviderLocator()

	assert.NotNil(t, locator)
	assert.NotNil(t, locator.exporters)
	assert.Empty(t, locator.exporters)
}

func TestNewProviderLocator_WithExporter(t *testing.T) {
	exporter1 := newMockExporter("exporter1")
	exporter2 := newMockExporter("exporter2")

	locator := NewProviderLocator(
		WithExporter("exporter1", exporter1),
		WithExporter("exporter2", exporter2),
	)

	assert.NotNil(t, locator)
	assert.Len(t, locator.exporters, 2)
	assert.Equal(t, exporter1, locator.exporters["exporter1"])
	assert.Equal(t, exporter2, locator.exporters["exporter2"])
}

func TestNewProviderLocator_WithExporter_OverwritesSameName(t *testing.T) {
	exporter1 := newMockExporter("exporter")
	exporter2 := newMockExporter("exporter")

	locator := NewProviderLocator(
		WithExporter("exporter", exporter1),
		WithExporter("exporter", exporter2),
	)

	assert.Len(t, locator.exporters, 1)
	assert.Equal(t, exporter2, locator.exporters["exporter"])
}

func TestGetExporter_Success(t *testing.T) {
	configuredExporter := newMockExporter("kafka")
	baseExporter := newMockExporter("kafka")
	baseExporter.withSettingsExporter = configuredExporter

	locator := NewProviderLocator(
		WithExporter("kafka", baseExporter),
	)

	dto := types.ExporterDTO{
		Name: "kafka",
		Settings: map[string]interface{}{
			"broker": "localhost:9092",
		},
	}

	result, err := locator.GetExporter(dto)

	assert.NoError(t, err)
	assert.Equal(t, configuredExporter, result)
}

func TestGetExporter_UnknownProvider(t *testing.T) {
	locator := NewProviderLocator()

	dto := types.ExporterDTO{
		Name: "unknown",
	}

	result, err := locator.GetExporter(dto)

	assert.Nil(t, result)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown provider: unknown")
}

func TestGetExporter_ValidationError(t *testing.T) {
	exporter := newMockExporter("kafka")
	exporter.validateErr = errors.New("invalid broker address")

	locator := NewProviderLocator(
		WithExporter("kafka", exporter),
	)

	dto := types.ExporterDTO{
		Name: "kafka",
		Settings: map[string]interface{}{
			"broker": "",
		},
	}

	result, err := locator.GetExporter(dto)

	assert.Nil(t, result)
	assert.Error(t, err)
	assert.Equal(t, "invalid broker address", err.Error())
}

func TestGetExporter_WithSettingsError(t *testing.T) {
	exporter := newMockExporter("kafka")
	exporter.withSettingsErr = errors.New("failed to create exporter with settings")

	locator := NewProviderLocator(
		WithExporter("kafka", exporter),
	)

	dto := types.ExporterDTO{
		Name: "kafka",
		Settings: map[string]interface{}{
			"broker": "localhost:9092",
		},
	}

	result, err := locator.GetExporter(dto)

	assert.Nil(t, result)
	assert.Error(t, err)
	assert.Equal(t, "failed to create exporter with settings", err.Error())
}

func TestValidateExporter_Success(t *testing.T) {
	exporter := newMockExporter("kafka")

	locator := NewProviderLocator(
		WithExporter("kafka", exporter),
	)

	dto := types.ExporterDTO{
		Name: "kafka",
		Settings: map[string]interface{}{
			"broker": "localhost:9092",
		},
	}

	err := locator.ValidateExporter(dto)

	assert.NoError(t, err)
}

func TestValidateExporter_UnknownProvider(t *testing.T) {
	locator := NewProviderLocator()

	dto := types.ExporterDTO{
		Name: "unknown",
	}

	err := locator.ValidateExporter(dto)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown provider: unknown")
}

func TestValidateExporter_ValidationError(t *testing.T) {
	exporter := newMockExporter("kafka")
	exporter.validateErr = errors.New("broker is required")

	locator := NewProviderLocator(
		WithExporter("kafka", exporter),
	)

	dto := types.ExporterDTO{
		Name:     "kafka",
		Settings: map[string]interface{}{},
	}

	err := locator.ValidateExporter(dto)

	assert.Error(t, err)
	assert.Equal(t, "broker is required", err.Error())
}


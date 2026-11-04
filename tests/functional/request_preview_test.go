//go:build functional

package functional_test

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const requestPreviewProxyPortOffset = 160

func otlpExporterList(name, endpoint string) string {
	return fmt.Sprintf(`[{name: %s, type: otlp, settings: {endpoint: %q, protocol: http/protobuf, insecure: true, compression: none}}]`, name, endpoint)
}

// TestRequestPreview_TravelsOnTheRawRecordOnly boots a proxy plane with a raw
// and a metadata OTLP exporter and checks that the start of the prompt reaches
// the raw collector only: it is body content, like the body it comes from.
func TestRequestPreview_TravelsOnTheRawRecordOnly(t *testing.T) {
	defer Track(t, "RequestPreview")()

	rawReceiver := newOTLPReceiver(t)
	metadataReceiver := newOTLPReceiver(t)
	tenant := usageTenantGateway(t, uniqueName("preview"), "request-preview-marker")
	base := startStoreProxyPlaneAt(t, GlobalConfig.Server.ProxyPort+requestPreviewProxyPortOffset,
		"TELEMETRY_EXPORTERS_FILE=",
		"TELEMETRY_EXPORTERS_METADATA="+otlpExporterList("metadata-collector", metadataReceiver.server.URL),
		"TELEMETRY_EXPORTERS_RAW="+otlpExporterList("raw-collector", rawReceiver.server.URL),
	)
	require.True(t, pollProxyServedAt(t, base, tenant.apiKey, tenant.path, "request-preview-marker", 30*time.Second),
		"the proxy plane never served the tenant")

	status, headers, body := proxyPostAt(t, base, tenant.apiKey, tenant.path, map[string]any{
		"model": "gpt-4o-mini",
		"messages": []map[string]string{
			{"role": "system", "content": "You are the ACME assistant."},
			{"role": "user", "content": "an earlier turn"},
			{"role": "assistant", "content": "ok"},
			{"role": "user", "content": "  Summarise   the attached\n\ncontract  "},
		},
	})
	require.Equal(t, http.StatusOK, status, "body=%s", body)
	traceID := headers.Get("X-AG-Trace-Id")
	require.NotEmpty(t, traceID)

	trace := otlpStringAttr("trustgate.trace_id", traceID)
	preview := otlpStringAttr("trustgate.request.preview", "Summarise the attached contract")
	require.Eventually(t, func() bool { return otlpRecordWith(rawReceiver, trace, preview) }, 30*time.Second, 250*time.Millisecond,
		"the raw record never carried the request preview")
	require.Eventually(t, func() bool { return otlpRecordWith(metadataReceiver, trace) }, 30*time.Second, 250*time.Millisecond,
		"the metadata record never arrived")
	assert.False(t, metadataReceiver.contains("trustgate.request.preview"), "the metadata record must not carry the preview")
	assert.False(t, metadataReceiver.contains("Summarise the attached"), "nor any of the prompt")
}

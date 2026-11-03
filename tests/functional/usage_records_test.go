//go:build functional

package functional_test

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const usageRecordsProxyPortOffset = 140

func proxyGetAt(t *testing.T, base, apiKey, path string) (int, http.Header) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, base+path, nil)
	require.NoError(t, err)
	host, ok := proxyHosts.Load(apiKey)
	require.True(t, ok, "proxy host missing for api key")
	req.Host = host.(string)
	req.Header.Set(proxyAPIKeyHeader, apiKey)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	return resp.StatusCode, resp.Header
}

// hasUsageRecord reports whether the receiver got the usage record of the
// request traced by traceID. The usage exporter always gzips its batches.
func hasUsageRecord(t *testing.T, r *otlpReceiver, traceID string) bool {
	t.Helper()
	want := otlpStringAttr("usage.event_id", "trustgate:"+traceID)
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, body := range r.bodies {
		zr, err := gzip.NewReader(bytes.NewReader(body))
		require.NoError(t, err)
		raw, err := io.ReadAll(zr)
		require.NoError(t, err)
		if bytes.Contains(raw, want) {
			return true
		}
	}
	return false
}

// TestUsageRecords_ModelListingsAreNotBilled boots a proxy plane that emits
// usage records to a local OTLP receiver and checks that listing or reading
// models emits none, while a served chat request does.
func TestUsageRecords_ModelListingsAreNotBilled(t *testing.T) {
	defer Track(t, "UsageRecords")()

	receiver := newOTLPReceiver(t)
	tenant := usageTenantGateway(t, uniqueName("usage-records"), "usage-records-marker")
	base := startStoreProxyPlaneAt(t, GlobalConfig.Server.ProxyPort+usageRecordsProxyPortOffset,
		"USAGE_RECORDS_ENABLED=true",
		"USAGE_RECORDS_OTLP_ENDPOINT="+receiver.server.URL,
		"USAGE_RECORDS_OTLP_PROTOCOL=http/protobuf",
		"USAGE_RECORDS_OTLP_INSECURE=true",
	)
	require.True(t, pollProxyServedAt(t, base, tenant.apiKey, tenant.path, "usage-records-marker", 30*time.Second),
		"the proxy plane never served the tenant")

	modelsPath := strings.TrimSuffix(tenant.path, "/chat/completions") + "/models"
	var listingTraces []string
	for _, path := range []string{modelsPath, modelsPath, modelsPath + "/gpt-4o-mini"} {
		status, headers := proxyGetAt(t, base, tenant.apiKey, path)
		require.Contains(t, []int{http.StatusOK, http.StatusNotFound}, status, "path %s", path)
		traceID := headers.Get("X-AG-Trace-Id")
		require.NotEmpty(t, traceID, "path %s has no trace id", path)
		listingTraces = append(listingTraces, traceID)
	}

	status, headers, body := proxyPostAt(t, base, tenant.apiKey, tenant.path, chatRequest(false))
	require.Equal(t, http.StatusOK, status, "body=%s", body)
	chatTrace := headers.Get("X-AG-Trace-Id")
	require.NotEmpty(t, chatTrace)

	require.Eventually(t, func() bool { return hasUsageRecord(t, receiver, chatTrace) }, 30*time.Second, 250*time.Millisecond,
		"the chat request never emitted its usage record")
	for _, traceID := range listingTraces {
		assert.False(t, hasUsageRecord(t, receiver, traceID), "a models request emitted a usage record (trace %s)", traceID)
	}
}

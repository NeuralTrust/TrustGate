//go:build functional

package functional_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type softDeleteRoute struct {
	gatewayID  string
	consumerID string
	apiKey     string
	path       string
}

func setupSoftDeleteRoute(t *testing.T, upstreamURL string) softDeleteRoute {
	t.Helper()
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("soft-del-gw")})
	registryID := CreateRegistry(t, gatewayID, openaiBackendPayload(uniqueName("be"), upstreamURL))
	consumerID := CreateConsumer(t, gatewayID, map[string]any{"name": uniqueName("soft-del-co")})
	AttachRegistry(t, gatewayID, consumerID, registryID)
	return softDeleteRoute{
		gatewayID:  gatewayID,
		consumerID: consumerID,
		apiKey:     createAndAttachAPIKey(t, gatewayID, consumerID),
		path:       chatCompletionsPath(t, consumerID),
	}
}

func deleteConsumer(t *testing.T, gatewayID, consumerID string) {
	t.Helper()
	status, body := sendRequest(t, http.MethodDelete,
		fmt.Sprintf("%s/v1/gateways/%s/consumers/%s", AdminURL, gatewayID, consumerID), nil, nil)
	require.Equal(t, http.StatusNoContent, status, "body=%v", body)
}

func listedConsumerIDs(t *testing.T, gatewayID string) []string {
	t.Helper()
	status, body := sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/consumers?size=100", AdminURL, gatewayID), nil, nil)
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	items, ok := body["items"].([]any)
	require.True(t, ok, "list response missing items: %v", body)
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, fmt.Sprint(item.(map[string]any)["id"]))
	}
	return out
}

func TestSoftDeleteConsumer_KeyIsRefusedAndTheSlugStopsRouting(t *testing.T) {
	defer Track(t, "SoftDeleteConsumer")()
	upstream := newJSONUpstream(t, "soft-delete-marker")
	route := setupSoftDeleteRoute(t, upstream.URL())

	status, _, body := proxyPost(t, route.apiKey, route.path, chatRequest(false))
	require.Equal(t, http.StatusOK, status, "the live consumer must serve: %s", body)
	hits := upstream.Hits()
	whoStatus, who := whoAmIOnGateway(t, route.gatewayID, route.apiKey)
	require.Equal(t, http.StatusOK, whoStatus, "body=%v", who)
	require.NotEmpty(t, who["consumers"], "the live key reaches its consumer: %v", who)

	deleteConsumer(t, route.gatewayID, route.consumerID)

	status, getBody := sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/consumers/%s", AdminURL, route.gatewayID, route.consumerID), nil, nil)
	require.Equal(t, http.StatusNotFound, status, "body=%v", getBody)
	assert.NotContains(t, listedConsumerIDs(t, route.gatewayID), route.consumerID)

	status, _, body = proxyPost(t, route.apiKey, route.path, chatRequest(false))
	assert.Equal(t, http.StatusNotFound, status, "a deleted consumer's slug must not route: %s", body)
	whoStatus, who = whoAmIOnGateway(t, route.gatewayID, route.apiKey)
	require.Equal(t, http.StatusOK, whoStatus, "body=%v", who)
	assert.Empty(t, who["consumers"], "a deleted consumer's key must reach no consumer: %v", who)
	assert.Equal(t, hits, upstream.Hits(), "nothing may reach the upstream through a deleted consumer")

	status, delBody := sendRequest(t, http.MethodDelete,
		fmt.Sprintf("%s/v1/gateways/%s/consumers/%s", AdminURL, route.gatewayID, route.consumerID), nil, nil)
	require.Equal(t, http.StatusNotFound, status, "a second delete finds nothing, body=%v", delBody)
}

func TestSoftDeleteConsumer_NameCanBeReused(t *testing.T) {
	defer Track(t, "SoftDeleteConsumer")()
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("soft-del-reuse-gw")})
	name := uniqueName("soft-del-reuse")
	first := CreateConsumer(t, gatewayID, validConsumerPayload(name))

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/consumers", AdminURL, gatewayID), nil, validConsumerPayload(name))
	require.Equal(t, http.StatusConflict, status, "a live name stays unique, body=%v", body)

	deleteConsumer(t, gatewayID, first)
	second := CreateConsumer(t, gatewayID, validConsumerPayload(name))
	require.NotEqual(t, first, second)
	require.Equal(t, []string{second}, listedConsumerIDs(t, gatewayID))
}

func TestSoftDeleteConsumer_GatewayDeleteRemovesDeletedConsumers(t *testing.T) {
	defer Track(t, "SoftDeleteConsumer")()
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("soft-del-gw-cascade")})
	deleted := CreateConsumer(t, gatewayID, validConsumerPayload(uniqueName("soft-del-gone")))
	live := CreateConsumer(t, gatewayID, validConsumerPayload(uniqueName("soft-del-live")))
	deleteConsumer(t, gatewayID, deleted)

	status, body := sendRequest(t, http.MethodDelete, fmt.Sprintf("%s/v1/gateways/%s", AdminURL, gatewayID), nil, nil)
	require.Equal(t, http.StatusNoContent, status, "body=%v", body)

	conn := connectFunctionalDB(t)
	var remaining int
	require.NoError(t, conn.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM consumers WHERE id = ANY($1::uuid[])`, []string{deleted, live}).Scan(&remaining))
	require.Zero(t, remaining, "a gateway delete removes its consumers, deleted ones included")
}

// TestSoftDeleteConsumer_RequestInFlightFinishesAndTheNextIsRefused deletes the
// consumer while a request it admitted is still waiting on the upstream: the
// delete does not wait for it, the request still completes, and the key is
// refused from then on.
func TestSoftDeleteConsumer_RequestInFlightFinishesAndTheNextIsRefused(t *testing.T) {
	defer Track(t, "SoftDeleteConsumer")()
	arrived := make(chan struct{}, 1)
	release := make(chan struct{})
	var hits atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		hits.Add(1)
		select {
		case arrived <- struct{}{}:
		default:
		}
		<-release
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w,
			`{"id":"chatcmpl-test","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"in-flight-marker"},"finish_reason":"stop"}]}`)
	}))
	t.Cleanup(upstream.Close)
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	route := setupSoftDeleteRoute(t, upstream.URL)

	type result struct {
		status int
		body   []byte
	}
	done := make(chan result, 1)
	go func() {
		status, _, body := proxyPost(t, route.apiKey, route.path, chatRequest(false))
		done <- result{status: status, body: body}
	}()
	select {
	case <-arrived:
	case <-time.After(15 * time.Second):
		t.Fatal("the request never reached the upstream")
	}

	deleteConsumer(t, route.gatewayID, route.consumerID)
	close(release)

	select {
	case got := <-done:
		require.Equal(t, http.StatusOK, got.status, "the request admitted before the delete completes: %s", got.body)
		require.Contains(t, string(got.body), "in-flight-marker")
	case <-time.After(15 * time.Second):
		t.Fatal("the in-flight request never completed")
	}

	status, _, body := proxyPost(t, route.apiKey, route.path, chatRequest(false))
	assert.Equal(t, http.StatusNotFound, status, "the next request is refused: %s", body)
	assert.Equal(t, int64(1), hits.Load())
}

func TestSoftDeleteConsumer_DBLessPlaneDropsTheConsumer(t *testing.T) {
	defer Track(t, "SoftDeleteConsumer")()
	upstream := newJSONUpstream(t, "soft-delete-dbless-marker")
	route := setupSoftDeleteRoute(t, upstream.URL())

	port := GlobalConfig.Server.ProxyPort + 140
	lkgPath := filepath.Join(t.TempDir(), "snapshot.lkg")
	base, _ := startDBLessProxyPlane(t, port,
		dblessOverrides(lkgPath, dblessConfigSyncToken, uniqueName("soft-del-dbless"), port))
	require.True(t, pollDBLessReady(base, 30*time.Second), "db-less plane never became ready")
	require.True(t, pollProxyServedAt(t, base, route.apiKey, route.path, "soft-delete-dbless-marker", 30*time.Second),
		"db-less plane never served the live consumer")

	deleteConsumer(t, route.gatewayID, route.consumerID)

	deadline := time.Now().Add(30 * time.Second)
	var status int
	var body []byte
	for time.Now().Before(deadline) {
		status, _, body = proxyPostAt(t, base, route.apiKey, route.path, chatRequest(false))
		if status != http.StatusOK {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	assert.Equal(t, http.StatusNotFound, status, "the synced snapshot must drop the deleted consumer: %s", body)
}

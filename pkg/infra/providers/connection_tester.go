package providers

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

type ProbeStage string

const (
	StageConnectivity   ProbeStage = "connectivity"
	StageAuthentication ProbeStage = "authentication"
	StageProvider       ProbeStage = "provider"
	StageUnsupported    ProbeStage = "unsupported"
)

type ProbeResult struct {
	OK         bool
	Stage      ProbeStage
	StatusCode int
	Message    string
}

const ProbeHTTPTimeout = 10 * time.Second

//go:generate mockery --name=ConnectionTester --dir=. --output=./mocks --filename=connection_tester_mock.go --case=underscore --with-expecter
type ConnectionTester interface {
	TestConnection(ctx context.Context, config *Config) ProbeResult
}

var probePool = NewHTTPClientPool()

func RunHTTPProbe(providerKey string, req *http.Request) ProbeResult {
	client := probePool.Get(providerKey+"-probe", ProbeHTTPTimeout)
	resp, err := client.Do(req) // #nosec G704 -- probe URL is built by the provider wrapper, not user input
	if err != nil {
		return ProbeResult{
			OK:      false,
			Stage:   StageConnectivity,
			Message: fmt.Sprintf("could not reach provider: %s", err.Error()),
		}
	}
	defer DrainBody(resp.Body)
	return ClassifyProbeStatusForProvider(providerKey, resp.StatusCode)
}

func RunBearerGETProbe(ctx context.Context, providerKey, url, apiKey string) ProbeResult {
	return RunAPIKeyGETProbe(ctx, providerKey, url, apiKey, func(req *http.Request, key string) {
		req.Header.Set("Authorization", "Bearer "+key)
	})
}

func RunAPIKeyGETProbe(
	ctx context.Context,
	providerKey string,
	url string,
	apiKey string,
	applyHeaders func(*http.Request, string),
) ProbeResult {
	if apiKey == "" {
		return ProbeResult{
			OK:      false,
			Stage:   StageAuthentication,
			Message: "api key is required",
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return ProbeResult{OK: false, Stage: StageConnectivity, Message: err.Error()}
	}
	applyHeaders(req, apiKey)
	return RunHTTPProbe(providerKey, req)
}

func ClassifyProbeStatus(statusCode int) ProbeResult {
	return classifyProbeStatus(statusCode)
}

func ClassifyProbeStatusForProvider(providerKey string, statusCode int) ProbeResult {
	if providerKey == ProviderGoogle && statusCode == http.StatusBadRequest {
		return ProbeResult{
			OK:         false,
			Stage:      StageAuthentication,
			StatusCode: statusCode,
			Message:    fmt.Sprintf("provider rejected the credentials (status %d)", statusCode),
		}
	}
	return classifyProbeStatus(statusCode)
}

func classifyProbeStatus(statusCode int) ProbeResult {
	switch {
	case statusCode >= http.StatusOK && statusCode < http.StatusMultipleChoices:
		return ProbeResult{OK: true, Stage: StageAuthentication, StatusCode: statusCode}
	case statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden:
		return ProbeResult{
			OK:         false,
			Stage:      StageAuthentication,
			StatusCode: statusCode,
			Message:    fmt.Sprintf("provider rejected the credentials (status %d)", statusCode),
		}
	default:
		return ProbeResult{
			OK:         false,
			Stage:      StageProvider,
			StatusCode: statusCode,
			Message:    fmt.Sprintf("provider returned an unexpected status (%d)", statusCode),
		}
	}
}

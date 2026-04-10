package httpx

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"

	domainUpstream "github.com/NeuralTrust/TrustGate/pkg/domain/upstream"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/sirupsen/logrus"
)

// HandleHTTPStream performs a streaming HTTP request to the given upstreamURL
// and pipes the SSE response back through the Fiber context, forwarding each
// payload to both streamResponse (metrics) and the plugin channel (via fiber locals).
func HandleHTTPStream(
	logger *logrus.Logger,
	client *http.Client,
	upstreamURL string,
	req *types.RequestContext,
	target *types.UpstreamTargetDTO,
	streamResponse chan []byte,
) (*types.ResponseContext, error) {

	httpReq, err := http.NewRequestWithContext(req.Context, req.Method, upstreamURL, bytes.NewReader(req.Body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	for k, values := range req.Headers {
		if k != "Host" {
			for _, v := range values {
				httpReq.Header.Add(k, v)
			}
		}
	}

	if httpReq.Header.Get("Content-Type") == "" {
		httpReq.Header.Set("Content-Type", "application/json")
	}
	if httpReq.Header.Get("Accept") == "" {
		httpReq.Header.Set("Accept", "text/event-stream")
	}
	httpReq.Header.Set("Cache-Control", "no-cache")
	httpReq.Header.Set("Connection", "keep-alive")

	if target.Credentials.HeaderValue != "" {
		httpReq.Header.Set(target.Credentials.HeaderName, target.Credentials.HeaderValue)
	}
	for k, v := range target.Headers {
		httpReq.Header.Set(k, v)
	}

	resp, err := client.Do(httpReq) // #nosec G704
	if err != nil {
		return nil, fmt.Errorf("failed to make streaming request: %w", err)
	}

	if domainUpstream.IsHTTPError(resp.StatusCode) {
		defer func() { _ = resp.Body.Close() }()
		var body []byte
		if resp.Body != nil {
			body, _ = io.ReadAll(resp.Body)
		}
		return nil, domainUpstream.NewUpstreamError(resp.StatusCode, body)
	}

	responseHeaders := make(map[string][]string)

	for key, values := range resp.Header {
		responseHeaders[key] = values
		for _, v := range values {
			req.C.Set(key, v)
		}
	}

	if rateLimitHeaders, ok := req.Metadata["rate_limit_headers"].(map[string][]string); ok {
		for k, v := range rateLimitHeaders {
			responseHeaders[k] = v
		}
	}

	req.C.Set("Content-Type", "text/event-stream")
	req.C.Set("Cache-Control", "no-cache")
	req.C.Set("Connection", "keep-alive")
	req.C.Set("X-Accel-Buffering", "no")

	fwd := newPayloadForwarder(req, streamResponse)

	req.C.Context().SetBodyStreamWriter(func(w *bufio.Writer) {
		defer func() { _ = resp.Body.Close() }()
		defer close(streamResponse)
		defer fwd.Close()

		reader := bufio.NewReader(resp.Body)
		for {
			line, err := reader.ReadBytes('\n')
			if len(line) > 0 {
				_, _ = w.Write(line)
				_ = w.Flush()
			}
			if err != nil {
				if err != io.EOF {
					logger.WithError(err).Error("error reading streaming response")
				}
				break
			}

			if bytes.HasPrefix(line, sseDataPrefix) {
				payload := bytes.TrimSpace(bytes.TrimPrefix(line, sseDataPrefix))
				if len(payload) > 0 && !bytes.Equal(payload, sseDoneMarker) {
					fwd.Send(payload)
				}
			}
		}
	})

	return &types.ResponseContext{
		StatusCode: resp.StatusCode,
		Headers:    responseHeaders,
		Streaming:  true,
		Metadata:   req.Metadata,
		Target:     target,
	}, nil
}

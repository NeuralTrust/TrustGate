package httpx

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

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

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "text/event-stream")
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

	if resp.StatusCode > 299 {
		defer func() { _ = resp.Body.Close() }()
		errorMsg := fmt.Sprintf("failed to make streaming request: %s", resp.Status)
		if resp.Body != nil {
			bodyBytes, readErr := io.ReadAll(resp.Body)
			if readErr == nil && len(bodyBytes) > 0 {
				errorMsg += fmt.Sprintf(" - body: %s", string(bodyBytes))
			}
		}
		return nil, errors.New(errorMsg)
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
			if err != nil {
				if err != io.EOF {
					logger.WithError(err).Error("error reading streaming response")
				}
				break
			}

			if bytes.HasPrefix(line, []byte("data: ")) {
				line = bytes.TrimPrefix(line, []byte("data: "))
			}

			if len(line) <= 1 {
				continue
			}

			var parsed map[string]interface{}
			if err := json.Unmarshal(line, &parsed); err != nil {
				fwd.Send(line)
				_, _ = fmt.Fprintf(w, "data: %s\n", string(line)) // #nosec G705
				_ = w.Flush()
				continue
			}

			var buffer bytes.Buffer
			encoder := json.NewEncoder(&buffer)
			encoder.SetEscapeHTML(false)

			if err := encoder.Encode(parsed); err != nil {
				logger.WithError(err).Error("error encoding stream payload")
				return
			}
			fwd.Send(buffer.Bytes())
			_, _ = fmt.Fprintf(w, "data: %s\n", buffer.String())
			_ = w.Flush()
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

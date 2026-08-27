// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"sync/atomic"
)

const (
	methodInitialize     = "initialize"
	methodServerDiscover = "server/discover"
	maxHandshakeBody     = 64 << 10

	codeMethodNotFound             = -32601
	codeHeaderMismatch             = -32020
	codeParameterHeaderMismatch    = -32021
	codeUnsupportedProtocolVersion = -32022
)

type handshakeRoundTripper struct {
	headers                 map[string]string
	transport               http.RoundTripper
	legacyFallback          bool
	protocolVersion         string
	discoverLegacyCandidate atomic.Bool
	initializeBadRequest    atomic.Bool
}

func (t *handshakeRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	for key, value := range t.headers {
		req.Header.Set(key, value)
	}

	method, id, ok := handshakeRequest(req)
	if t.legacyFallback && ok {
		switch method {
		case methodServerDiscover:
			return rejectDiscover(req, id)
		case methodInitialize:
			if t.protocolVersion != "" {
				offered, err := withProtocolVersion(req, t.protocolVersion)
				if err != nil {
					return nil, err
				}
				req = offered
			}
		}
	}

	resp, err := t.transport.RoundTrip(req)
	if err == nil && ok && method == methodServerDiscover && isLegacyDiscoverResponse(resp) {
		t.discoverLegacyCandidate.Store(true)
	}
	if err == nil && ok && method == methodInitialize && resp.StatusCode == http.StatusBadRequest {
		t.initializeBadRequest.Store(true)
	}
	return resp, err
}

func rejectRedirect(*http.Request, []*http.Request) error {
	return errors.New("MCP upstream redirects are not allowed")
}

func isLegacyDiscoverResponse(resp *http.Response) bool {
	if resp.Body == nil ||
		(resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusBadRequest) {
		return false
	}
	data, err := peekResponseBody(resp, maxHandshakeBody)
	if err != nil || len(data) > maxHandshakeBody {
		return false
	}

	var envelope struct {
		JSONRPC string          `json:"jsonrpc"`
		Result  json.RawMessage `json:"result"`
		Error   *struct {
			Code int64 `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil || envelope.JSONRPC != "2.0" {
		return resp.StatusCode == http.StatusBadRequest
	}
	if envelope.Error != nil {
		switch envelope.Error.Code {
		case codeMethodNotFound:
			return true
		case codeHeaderMismatch, codeParameterHeaderMismatch, codeUnsupportedProtocolVersion:
			return false
		default:
			return resp.StatusCode == http.StatusBadRequest
		}
	}
	return false
}

func peekResponseBody(resp *http.Response, limit int64) ([]byte, error) {
	body := resp.Body
	data, err := io.ReadAll(io.LimitReader(body, limit+1))
	resp.Body = &replayReadCloser{
		Reader: io.MultiReader(bytes.NewReader(data), body),
		closer: body,
	}
	return data, err
}

type replayReadCloser struct {
	io.Reader
	closer io.Closer
}

func (r *replayReadCloser) Close() error {
	return r.closer.Close()
}

func handshakeRequest(req *http.Request) (string, json.RawMessage, bool) {
	if req.Method != http.MethodPost || req.GetBody == nil {
		return "", nil, false
	}
	mediaType, _, err := mime.ParseMediaType(req.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return "", nil, false
	}
	body, err := req.GetBody()
	if err != nil {
		return "", nil, false
	}
	data, readErr := io.ReadAll(io.LimitReader(body, maxHandshakeBody+1))
	closeErr := body.Close()
	if readErr != nil || closeErr != nil || len(data) > maxHandshakeBody {
		return "", nil, false
	}
	var envelope struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Method  string          `json:"method"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil ||
		envelope.JSONRPC != "2.0" ||
		len(envelope.ID) == 0 ||
		envelope.Method == "" {
		return "", nil, false
	}
	return envelope.Method, envelope.ID, true
}

// withProtocolVersion returns a copy of an initialize request offering the
// given protocol revision. The revision is rewritten on the wire because the
// SDK keeps the equivalent client option unexported, so the version it offers
// on its legacy path cannot be chosen by a caller.
func withProtocolVersion(req *http.Request, version string) (*http.Request, error) {
	if req.GetBody == nil {
		return nil, errors.New("intercepted MCP initialize request has no replayable body")
	}
	body, err := req.GetBody()
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(body, maxHandshakeBody+1))
	closeErr := body.Close()
	switch {
	case readErr != nil:
		return nil, readErr
	case closeErr != nil:
		return nil, closeErr
	case len(data) > maxHandshakeBody:
		return nil, errors.New("intercepted MCP initialize request body is too large")
	}

	rewritten, err := rewriteProtocolVersion(data, version)
	if err != nil {
		return nil, err
	}
	if req.Body != nil {
		if err := req.Body.Close(); err != nil {
			return nil, err
		}
	}

	offered := req.Clone(req.Context())
	offered.Body = io.NopCloser(bytes.NewReader(rewritten))
	offered.ContentLength = int64(len(rewritten))
	offered.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(rewritten)), nil
	}
	return offered, nil
}

func rewriteProtocolVersion(data []byte, version string) ([]byte, error) {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, err
	}
	params := map[string]json.RawMessage{}
	if raw, ok := envelope["params"]; ok {
		if err := json.Unmarshal(raw, &params); err != nil {
			return nil, err
		}
	}
	encoded, err := json.Marshal(version)
	if err != nil {
		return nil, err
	}
	params["protocolVersion"] = encoded
	rawParams, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	envelope["params"] = rawParams
	return json.Marshal(envelope)
}

func rejectDiscover(req *http.Request, id json.RawMessage) (*http.Response, error) {
	if req.Body == nil {
		return nil, errors.New("intercepted MCP discover request has no body")
	}
	if err := req.Body.Close(); err != nil {
		return nil, errors.New("failed to close intercepted MCP discover request body")
	}
	body, err := json.Marshal(struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Error   struct {
			Code    int64  `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}{
		JSONRPC: "2.0",
		ID:      id,
		Error: struct {
			Code    int64  `json:"code"`
			Message string `json:"message"`
		}{
			Code:    -32601,
			Message: "Method not found",
		},
	})
	if err != nil {
		return nil, err
	}
	return &http.Response{
		Status:        "200 OK",
		StatusCode:    http.StatusOK,
		Header:        http.Header{"Content-Type": []string{"application/json"}},
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
	}, nil
}

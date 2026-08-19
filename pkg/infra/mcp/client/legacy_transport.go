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
)

const (
	methodServerDiscover              = "server/discover"
	maxLegacyDiscoverRequestBodyBytes = maxProbeBodyBytes
)

type legacyDiscoverRoundTripper struct {
	transport http.RoundTripper
}

func newLegacyDiscoverRoundTripper(transport http.RoundTripper) *legacyDiscoverRoundTripper {
	return &legacyDiscoverRoundTripper{transport: transport}
}

func (t *legacyDiscoverRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	id, ok := legacyDiscoverID(req)
	if !ok {
		return t.transport.RoundTrip(req)
	}
	if req.Body == nil {
		return t.transport.RoundTrip(req)
	}
	if err := req.Body.Close(); err != nil {
		return nil, errors.New("failed to close intercepted MCP request body")
	}
	body := make([]byte, 0, len(id)+96)
	body = append(body, `{"jsonrpc":"2.0","id":`...)
	body = append(body, id...)
	body = append(body, `,"error":{"code":-32601,"message":"Method not found"}}`...)
	return &http.Response{
		Status:        "200 OK",
		StatusCode:    http.StatusOK,
		Header:        http.Header{"Content-Type": []string{"application/json"}},
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
	}, nil
}

func legacyDiscoverID(req *http.Request) (json.RawMessage, bool) {
	if req.Method != http.MethodPost || req.GetBody == nil {
		return nil, false
	}
	mediaType, _, err := mime.ParseMediaType(req.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return nil, false
	}
	body, err := req.GetBody()
	if err != nil {
		return nil, false
	}
	data, readErr := io.ReadAll(io.LimitReader(body, maxLegacyDiscoverRequestBodyBytes+1))
	closeErr := body.Close()
	if readErr != nil || closeErr != nil || len(data) > maxLegacyDiscoverRequestBodyBytes {
		return nil, false
	}
	var envelope struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Method  string          `json:"method"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil ||
		envelope.JSONRPC != "2.0" ||
		envelope.Method != methodServerDiscover ||
		!validJSONRPCID(envelope.ID) {
		return nil, false
	}
	return envelope.ID, true
}

func validJSONRPCID(raw json.RawMessage) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var id any
	if err := decoder.Decode(&id); err != nil {
		return false
	}
	switch id.(type) {
	case string, json.Number:
		return true
	default:
		return false
	}
}

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

package a2a

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"time"

	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// provider is how the gateway talks to an agent where it is hosted. The
// caller's JSON-RPC call and the answer it gets are the same for every one.
type provider interface {
	// header adds the provider's headers to those of every request of x.
	header(x *Exchange, h http.Header)
	// request is the HTTP request that carries the JSON-RPC body to endpoint.
	request(ctx context.Context, endpoint string, h http.Header, body []byte) (*http.Request, error)
	// decode reads the agent's answer to a call that is not a stream.
	decode(x *Exchange, res *http.Response, body []byte) (json.RawMessage, *RPCError)
	// retry says how long to wait before sending a buffered call again after
	// its attempt-th answer was rpcErr, and false when it is not sent again.
	retry(rpcErr *RPCError, attempt int) (time.Duration, bool)
}

func providerOf(*registrydomain.A2ATarget) provider {
	return jsonrpc{}
}

// jsonrpc is an agent that speaks the JSON-RPC binding: the body goes as it
// is, the answer is a JSON-RPC response, and nothing is sent twice.
type jsonrpc struct{}

func (jsonrpc) header(*Exchange, http.Header) {}

func (jsonrpc) request(ctx context.Context, endpoint string, h http.Header, body []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header = h
	return req, nil
}

func (jsonrpc) decode(x *Exchange, res *http.Response, body []byte) (json.RawMessage, *RPCError) {
	return x.decode(body, res.StatusCode)
}

func (jsonrpc) retry(*RPCError, int) (time.Duration, bool) {
	return 0, false
}

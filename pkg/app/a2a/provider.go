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
	"strings"
	"time"

	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/google/uuid"
)

// provider is how the gateway talks to an agent where it is hosted. The
// caller's JSON-RPC call and the answer it gets are the same for every one.
type provider interface {
	// header adds the provider's headers to those of every request of x.
	header(x *Exchange, h http.Header)
	// request is the HTTP request that carries the JSON-RPC body to endpoint.
	request(ctx context.Context, endpoint string, h http.Header, body []byte) (*http.Request, error)
	// decode reads the agent's answer to a call that is not a stream, and
	// reports whether the error it returns is one the agent answered.
	decode(x *Exchange, res *http.Response, body []byte) (result json.RawMessage, rpcErr *RPCError, fromAgent bool)
	// retry says how long to wait before sending a buffered call again after
	// its attempt-th answer was rpcErr, and false when it is not sent again.
	retry(rpcErr *RPCError, attempt int) (time.Duration, bool)
	// capabilities is what the gateway can do with an agent hosted here.
	capabilities() capabilities
}

type capabilities struct {
	// streams is whether the gateway relays the agent's event streams.
	streams bool
	// jsonrpcOnlyCard is whether the served card must name the JSON-RPC
	// interface only, because the gateway translates every call.
	jsonrpcOnlyCard bool
}

func providerOf(t *registrydomain.A2ATarget) provider {
	switch t.Provider {
	case registrydomain.A2AProviderAzureFoundry:
		return foundry{}
	case registrydomain.A2AProviderBedrockAgentCore:
		return agentCore{}
	case registrydomain.A2AProviderVertexAgentEngine:
		return vertex{}
	default:
		return jsonrpc{}
	}
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

func (jsonrpc) decode(_ *Exchange, res *http.Response, body []byte) (json.RawMessage, *RPCError, bool) {
	return decodeRPC(body, res.StatusCode)
}

func (jsonrpc) retry(*RPCError, int) (time.Duration, bool) {
	return 0, false
}

func (jsonrpc) capabilities() capabilities {
	return capabilities{streams: true}
}

// foundry is a Microsoft Foundry agent: JSON-RPC, with the pinned version
// always named, since Foundry serves 0.3 to a request that names none.
type foundry struct{ jsonrpc }

func (foundry) header(x *Exchange, h http.Header) {
	h.Set("A2A-Version", string(x.version))
}

// ReasonUpstreamAuthFailed is the -32092 reason of an agent that refused the
// gateway's own credential.
const ReasonUpstreamAuthFailed = "upstream_auth_failed"

const (
	agentCoreSessionHeader = "X-Amzn-Bedrock-AgentCore-Runtime-Session-Id"
	// agentCoreSessionBusy and agentCoreSessionBusyMessage are how AgentCore
	// answers a call that reached a session still running another one. The
	// code alone also covers session errors that a retry does not fix.
	agentCoreSessionBusy        = -32054
	agentCoreSessionBusyMessage = "Session operation in progress"
)

// agentCoreRetryWait is how long to wait before each retry of a call that
// found its AgentCore session busy.
var agentCoreRetryWait = []time.Duration{100 * time.Millisecond, 400 * time.Millisecond}

// agentCore is an Amazon Bedrock AgentCore runtime: JSON-RPC in a runtime
// session, with errors carried by their real HTTP status.
type agentCore struct{ jsonrpc }

// header sends the session of the task or context the call names, or a new
// one that the answer's task and context then keep.
func (agentCore) header(x *Exchange, h http.Header) {
	if x.session == "" {
		x.session = "tgs-" + uuid.Must(uuid.NewV7()).String()
	}
	h.Set(agentCoreSessionHeader, x.session)
}

// decode reads a JSON-RPC answer whatever its status. A 401 that asks for
// authentication is the user identity refused; a 403 without a JSON-RPC
// error is the gateway's SigV4 signature refused.
func (agentCore) decode(_ *Exchange, res *http.Response, body []byte) (json.RawMessage, *RPCError, bool) {
	if res.StatusCode == http.StatusUnauthorized && res.Header.Get("WWW-Authenticate") != "" {
		return nil, IdentityRequired(), false
	}
	result, rpcErr, fromAgent := decodeRPC(body, res.StatusCode)
	if rpcErr != nil && !fromAgent && res.StatusCode == http.StatusForbidden {
		return nil, GatewayFailure(ReasonUpstreamAuthFailed), false
	}
	return result, rpcErr, fromAgent
}

// retry sends a call again while its session is busy: AgentCore did not
// process it.
func (agentCore) retry(rpcErr *RPCError, attempt int) (time.Duration, bool) {
	if attempt >= len(agentCoreRetryWait) || rpcErr.Code != agentCoreSessionBusy ||
		!strings.Contains(rpcErr.Message, agentCoreSessionBusyMessage) {
		return 0, false
	}
	return agentCoreRetryWait[attempt], true
}

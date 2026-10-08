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
	"encoding/json"
	"errors"
	"strconv"
	"testing"

	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMapRPCError_RelaysGatewaySignalCodesUnderAGenericCode(t *testing.T) {
	for _, code := range []int64{-32001, -32003, -32004, -32005} {
		upstream := &jsonrpc.Error{
			Code:    code,
			Message: "from upstream",
			Data:    json.RawMessage(`{"connect_url":"https://example.test/connect"}`),
		}

		var rpcErr *appmcp.RPCError
		require.True(t, errors.As(mapRPCError(upstream), &rpcErr))

		assert.Equal(t, appmcp.CodeUpstreamError, rpcErr.Code, "code %d", code)
		assert.Equal(t, "from upstream", rpcErr.Message)
		var data map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(rpcErr.Data, &data))
		assert.JSONEq(t, `{"upstream_code":`+jsonNumber(code)+`,"upstream_data":{"connect_url":"https://example.test/connect"}}`, string(rpcErr.Data))
		assert.NotContains(t, data, "connect_url")
	}
}

func TestMapRPCError_KeepsOtherCodes(t *testing.T) {
	for _, code := range []int64{-32002, -32602, -32603, -32000, 42} {
		upstream := &jsonrpc.Error{Code: code, Message: "m", Data: json.RawMessage(`{"k":1}`)}

		var rpcErr *appmcp.RPCError
		require.True(t, errors.As(mapRPCError(upstream), &rpcErr))

		assert.Equal(t, code, rpcErr.Code)
		assert.JSONEq(t, `{"k":1}`, string(rpcErr.Data))
	}
}

func TestMapRPCError_UpstreamPolicyCodeIsNotCountedAsAGatewayDenial(t *testing.T) {
	var rpcErr *appmcp.RPCError
	require.True(t, errors.As(mapRPCError(&jsonrpc.Error{Code: -32001, Message: "no"}), &rpcErr))

	assert.False(t, appmcp.IsPolicyBlockedCode(rpcErr.Code))
	assert.JSONEq(t, `{"upstream_code":-32001}`, string(rpcErr.Data))
}

func jsonNumber(n int64) string {
	return strconv.FormatInt(n, 10)
}

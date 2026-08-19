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
	"fmt"

	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
)

const (
	codeHeaderMismatch             int64 = -32020
	codeRequiredCapability         int64 = -32021
	codeUnsupportedProtocolVersion int64 = -32022
)

type unreachableError struct {
	origin   string
	category string
	cause    error
}

func (e *unreachableError) Error() string {
	if e.origin == "" {
		return fmt.Sprintf("%s: %s", appmcp.ErrUnreachable, e.category)
	}
	return fmt.Sprintf("%s: %s: %s", appmcp.ErrUnreachable, e.category, e.origin)
}

func (e *unreachableError) Unwrap() []error {
	return []error{appmcp.ErrUnreachable, e.cause}
}

func wrapUnreachable(origin, category string, err error) error {
	return &unreachableError{origin: origin, category: category, cause: err}
}

func mapRPCError(err error) error {
	if err == nil {
		return nil
	}
	if je, ok := errors.AsType[*jsonrpc.Error](err); ok {
		return &appmcp.RPCError{Code: je.Code, Message: je.Message, Data: je.Data}
	}
	return err
}

func probeRPCError(err error) (*jsonrpc.Error, bool) {
	if err == nil {
		return nil, false
	}
	rpcErr, ok := errors.AsType[*jsonrpc.Error](err)
	return rpcErr, ok
}

func isModernProofRPCCode(code int64) bool {
	switch code {
	case codeHeaderMismatch, codeRequiredCapability, codeUnsupportedProtocolVersion:
		return true
	default:
		return false
	}
}

func mapItems[T any](method string, items any) ([]T, error) {
	raw, err := json.Marshal(items)
	if err != nil {
		return nil, fmt.Errorf("mcp client: %s: encode items: %w", method, err)
	}
	var out []T
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("mcp client: %s: map items: %w", method, err)
	}
	return out, nil
}

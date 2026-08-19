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

func wrapUnreachable(url string, err error) error {
	return fmt.Errorf("%w: %s: %w", appmcp.ErrUnreachable, url, err)
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

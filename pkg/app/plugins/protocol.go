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

package plugins

import (
	"errors"
	"fmt"
)

type Protocol string

const (
	ProtocolLLM Protocol = "LLM"
	ProtocolMCP Protocol = "MCP"
	ProtocolA2A Protocol = "A2A"
)

var ErrInvalidProtocols = errors.New("plugin: invalid declared protocols")

func (p Protocol) IsValid() bool {
	switch p {
	case ProtocolLLM, ProtocolMCP, ProtocolA2A:
		return true
	}
	return false
}

func validateDeclaredProtocols(name string, protocols []Protocol) error {
	if len(protocols) == 0 {
		return fmt.Errorf("%w: %s declares no supported protocols", ErrInvalidProtocols, name)
	}
	for _, p := range protocols {
		if !p.IsValid() {
			return fmt.Errorf("%w: %s supports %q", ErrInvalidProtocols, name, p)
		}
	}
	return nil
}

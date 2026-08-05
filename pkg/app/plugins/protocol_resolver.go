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

// ProtocolConfigValidator is implemented by plugins that serve more than one
// protocol and whose settings do not all mean something on each of them. A
// plugin supporting a protocol only says the chain will run; a setting that the
// chosen protocol cannot honour is accepted at policy creation, where no
// consumer is in sight, so the check has to happen when the two meet.
type ProtocolConfigValidator interface {
	ValidateConfigForProtocol(protocol Protocol, settings map[string]any) error
}

type ProtocolResolver struct {
	registry Registry
}

func NewProtocolResolver(registry Registry) *ProtocolResolver {
	return &ProtocolResolver{registry: registry}
}

func (r *ProtocolResolver) SupportedProtocols(slug string) ([]string, bool) {
	p, ok := r.registry.Get(slug)
	if !ok {
		return nil, false
	}
	protocols := p.SupportedProtocols()
	out := make([]string, 0, len(protocols))
	for _, protocol := range protocols {
		out = append(out, string(protocol))
	}
	return out, true
}

// ValidateSettingsForProtocol reports whether a policy's settings mean on this
// protocol what they say. Plugins that do not care return nil by not
// implementing ProtocolConfigValidator.
func (r *ProtocolResolver) ValidateSettingsForProtocol(
	slug string,
	protocol string,
	settings map[string]any,
) error {
	p, ok := r.registry.Get(slug)
	if !ok {
		return nil
	}
	validator, ok := p.(ProtocolConfigValidator)
	if !ok {
		return nil
	}
	return validator.ValidateConfigForProtocol(Protocol(protocol), settings)
}

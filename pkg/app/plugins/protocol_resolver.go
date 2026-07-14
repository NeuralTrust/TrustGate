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

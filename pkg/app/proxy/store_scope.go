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

package proxy

import (
	"slices"
	"strings"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	domainconsumer "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	routingdomain "github.com/NeuralTrust/TrustGate/pkg/domain/routing"
)

type scopedLink struct {
	appconsumer.StoreLink
	substituted []string
}

func storeScope(links []appconsumer.StoreLink) []scopedLink {
	var substituted []string
	for _, link := range links {
		if link.Link.Level != domainconsumer.GrantLevelUser {
			continue
		}
		for _, reg := range link.Consumer.Registries {
			if p := registryProvider(reg); p != "" && !slices.Contains(substituted, p) {
				substituted = append(substituted, p)
			}
		}
	}
	out := make([]scopedLink, 0, len(links))
	for _, link := range links {
		scoped := scopedLink{StoreLink: link}
		if link.Link.Level != domainconsumer.GrantLevelUser {
			scoped.substituted = substituted
		}
		if slices.ContainsFunc(link.Consumer.Registries, scoped.keepsRegistry) {
			out = append(out, scoped)
		}
	}
	return out
}

func (l *scopedLink) keepsRegistry(reg *domain.Registry) bool {
	return !slices.Contains(l.substituted, registryProvider(reg))
}

func (l *scopedLink) filter() CandidateFilter {
	if len(l.substituted) == 0 {
		return nil
	}
	return func(c routingdomain.Candidate) bool { return l.keepsRegistry(c.Registry) }
}

func (l *scopedLink) primaryFilter() CandidateFilter {
	return func(c routingdomain.Candidate) bool { return !c.FallbackOnly() && l.keepsRegistry(c.Registry) }
}

func registryProvider(reg *domain.Registry) string {
	if reg == nil {
		return ""
	}
	return strings.ToLower(reg.Provider())
}

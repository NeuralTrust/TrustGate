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

package secretref

import (
	"context"
	"fmt"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/common/secret"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/secretref"
)

// policySettingsKey prefixes a plugin's credential path in a policy's
// declared locations.
const policySettingsKey = "settings"

// PolicyRefs lists the plugin credential paths of p that hold a reference or
// embed one, and where p sends them: its plugin and the values at the
// plugin's declared destination paths (an endpoint, a location). hosts are the
// hosts the plugin sends those credentials to under p's settings.
func PolicyRefs(p *policy.Policy, paths, destinations, hosts []string) EntityRefs {
	hosts = hostList(hosts...)
	refs := EntityRefs{GatewayID: p.GatewayID, Entity: domain.EntityPolicy, ID: p.ID.String()}
	for _, path := range paths {
		v, ok := secret.SettingString(p.Settings, path)
		if !ok {
			continue
		}
		loc := append([]string{policySettingsKey}, strings.Split(path, ".")...)
		switch {
		case domain.IsRef(v):
			refs.Uses = append(refs.Uses, Use{Path: loc, Raw: v, Hosts: hosts})
		case domain.ContainsRef(v):
			refs.Embedded = append(refs.Embedded, Use{Path: loc, Raw: v})
		}
	}
	dest := []string{p.Slug}
	for _, path := range destinations {
		v, _ := secret.SettingString(p.Settings, path)
		dest = append(dest, path+"="+fmt.Sprint(v))
	}
	refs.Destination = strings.Join(dest, "\x00")
	return refs
}

// PluginCredentials returns, for a policy, its plugin's credential paths and
// the hosts its settings send them to.
type PluginCredentials func(p *policy.Policy) (paths, hosts []string)

// GatewayPolicies returns policies with every one whose plugin credentials
// hold a reference replaced by a copy carrying the resolved values, or empty
// ones where they do not resolve. It records what the gateway's policies use,
// so a change invalidates the gateway. The input policies are never modified.
func GatewayPolicies(ctx context.Context, r ValuesResolver, gatewayID ids.GatewayID, policies []*policy.Policy, creds PluginCredentials) []*policy.Policy {
	type owner struct {
		index int
		path  string
	}
	var uses []Use
	var owners []owner
	for i, p := range policies {
		if p == nil {
			continue
		}
		paths, hosts := creds(p)
		for _, u := range PolicyRefs(p, paths, nil, hosts).Uses {
			uses = append(uses, u)
			owners = append(owners, owner{index: i, path: strings.Join(u.Path[1:], ".")})
		}
	}
	resolved := r.Values(ctx, gatewayID, SourcePolicies, uses)
	if len(uses) == 0 {
		return policies
	}
	values := map[int]map[string]string{}
	for i, o := range owners {
		if values[o.index] == nil {
			values[o.index] = map[string]string{}
		}
		values[o.index][o.path] = resolved[i].Value
	}
	out := append([]*policy.Policy(nil), policies...)
	for index, set := range values {
		cp := *policies[index]
		cp.Settings = secret.WithSettingStrings(policies[index].Settings, set)
		out[index] = &cp
	}
	return out
}

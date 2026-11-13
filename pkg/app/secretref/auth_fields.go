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
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/secretref"
)

// AuthRefs lists the identity provider secrets of a that hold a reference or
// embed one, and where a sends them: the provider's issuer and endpoints.
func AuthRefs(a *auth.Auth) EntityRefs {
	refs := EntityRefs{GatewayID: a.GatewayID, Entity: domain.EntityAuth, ID: a.ID.String()}
	c := a.Config.OAuth2
	if c == nil {
		return refs
	}
	refs.Destination = strings.Join([]string{c.Issuer, c.TokenURL, c.AuthorizeURL, c.IntrospectionURL, c.UserInfoURL, c.JWKSURL}, "\x00")
	for _, f := range []struct {
		key, value string
		hosts      []string
	}{
		{"client_secret", c.ClientSecret, hostList(c.TokenURL, c.IntrospectionURL)},
		{"exchange_client_secret", c.ExchangeClientSecret, hostList(c.TokenURL)},
	} {
		path := []string{"config", "oauth2", f.key}
		switch {
		case domain.IsRef(f.value):
			refs.Uses = append(refs.Uses, Use{Path: path, Raw: f.value, Hosts: f.hosts})
		case domain.ContainsRef(f.value):
			refs.Embedded = append(refs.Embedded, Use{Path: path, Raw: f.value})
		}
	}
	return refs
}

// GatewayAuths returns auths with every one whose identity provider secrets
// hold a reference replaced by a copy carrying the resolved values, or empty
// ones where they do not resolve. source names the part of the gateway's
// runtime data the auths build. The input auths are never modified.
func GatewayAuths(ctx context.Context, r ValuesResolver, gatewayID ids.GatewayID, source string, auths []*auth.Auth) []*auth.Auth {
	type owner struct {
		index int
		key   string
	}
	var uses []Use
	var owners []owner
	for i, a := range auths {
		if a == nil {
			continue
		}
		for _, u := range AuthRefs(a).Uses {
			uses = append(uses, u)
			owners = append(owners, owner{index: i, key: u.Path[len(u.Path)-1]})
		}
	}
	resolved := r.Values(ctx, gatewayID, source, uses)
	if len(uses) == 0 {
		return auths
	}
	out := append([]*auth.Auth(nil), auths...)
	copied := map[int]bool{}
	for i, o := range owners {
		if !copied[o.index] {
			cp := *auths[o.index]
			cfg := *cp.Config.OAuth2
			cp.Config.OAuth2 = &cfg
			out[o.index] = &cp
			copied[o.index] = true
		}
		cfg := out[o.index].Config.OAuth2
		switch o.key {
		case "client_secret":
			cfg.ClientSecret = resolved[i].Value
		case "exchange_client_secret":
			cfg.ExchangeClientSecret = resolved[i].Value
		}
	}
	return out
}

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
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/secretref"
)

// slot is the value at one declared location of a registry.
type slot struct {
	path  []string
	value string
	hosts []string
}

const headersKey = "headers"

// registryHasRef reports whether any declared location of r holds a
// reference-shaped value. It allocates nothing, so a registry without
// references costs a few comparisons.
func registryHasRef(r *registry.Registry) bool {
	if r == nil {
		return false
	}
	if t := r.LLMTarget; t != nil {
		if a := t.Auth; a != nil {
			if k := a.APIKey; k != nil && (domain.IsRef(k.APIKey) || domain.IsRef(k.HeaderValue) || domain.IsRef(k.ParamValue)) {
				return true
			}
			if w := a.AWS; w != nil && (domain.IsRef(w.AccessKeyID) || domain.IsRef(w.SecretAccessKey) || domain.IsRef(w.SessionToken)) {
				return true
			}
			if z := a.Azure; z != nil && (domain.IsRef(z.APIKey) || domain.IsRef(z.ClientSecret)) {
				return true
			}
			if o := a.OAuth; o != nil && (domain.IsRef(o.ClientSecret) || domain.IsRef(o.RefreshToken) || domain.IsRef(o.Password)) {
				return true
			}
			if a.GCPServiceAccount != nil && domain.IsRef(*a.GCPServiceAccount) {
				return true
			}
		}
		switch headers := t.ProviderOptions[headersKey].(type) {
		case map[string]any:
			for _, v := range headers {
				if s, ok := v.(string); ok && domain.IsRef(s) {
					return true
				}
			}
		case map[string]string:
			for _, v := range headers {
				if domain.IsRef(v) {
					return true
				}
			}
		}
	}
	if t := r.MCPTarget; t != nil {
		if a := t.Auth; a != nil && (domain.IsRef(a.Value) || domain.IsRef(a.ClientSecret)) {
			return true
		}
		for _, v := range t.Headers {
			if domain.IsRef(v) {
				return true
			}
		}
	}
	if t := r.A2ATarget; t != nil {
		if a := t.Auth; a != nil && (domain.IsRef(a.Value) || domain.IsRef(a.ClientSecret)) {
			return true
		}
		for _, v := range t.Headers {
			if domain.IsRef(v) {
				return true
			}
		}
		if c := t.CloudAuth; c != nil {
			if w := c.AWS; w != nil && (domain.IsRef(w.AccessKeyID) || domain.IsRef(w.SecretAccessKey) || domain.IsRef(w.SessionToken)) {
				return true
			}
			if c.Azure != nil && domain.IsRef(c.Azure.ClientSecret) {
				return true
			}
			if c.GCP != nil && domain.IsRef(c.GCP.ServiceAccountJSON) {
				return true
			}
		}
	}
	return false
}

// registrySlots lists the declared locations of r that hold a
// reference-shaped value.
func registrySlots(r *registry.Registry) []slot {
	var out []slot
	add := func(value string, path ...string) {
		if domain.IsRef(value) {
			out = append(out, slot{path: path, value: value, hosts: registryHosts(r, path)})
		}
	}
	if t := r.LLMTarget; t != nil {
		if a := t.Auth; a != nil {
			if k := a.APIKey; k != nil {
				add(k.APIKey, "llm_target", "auth", "api_key", "api_key")
				add(k.HeaderValue, "llm_target", "auth", "api_key", "header_value")
				add(k.ParamValue, "llm_target", "auth", "api_key", "param_value")
			}
			if w := a.AWS; w != nil {
				add(w.AccessKeyID, "llm_target", "auth", "aws", "access_key_id")
				add(w.SecretAccessKey, "llm_target", "auth", "aws", "secret_access_key")
				add(w.SessionToken, "llm_target", "auth", "aws", "session_token")
			}
			if z := a.Azure; z != nil {
				add(z.APIKey, "llm_target", "auth", "azure", "api_key")
				add(z.ClientSecret, "llm_target", "auth", "azure", "client_secret")
			}
			if o := a.OAuth; o != nil {
				add(o.ClientSecret, "llm_target", "auth", "oauth", "client_secret")
				add(o.RefreshToken, "llm_target", "auth", "oauth", "refresh_token")
				add(o.Password, "llm_target", "auth", "oauth", "password")
			}
			if a.GCPServiceAccount != nil {
				add(*a.GCPServiceAccount, "llm_target", "auth", "gcp_service_account")
			}
		}
		switch headers := t.ProviderOptions[headersKey].(type) {
		case map[string]any:
			for k, v := range headers {
				if s, ok := v.(string); ok {
					add(s, "llm_target", "provider_options", headersKey, k)
				}
			}
		case map[string]string:
			for k, v := range headers {
				add(v, "llm_target", "provider_options", headersKey, k)
			}
		}
	}
	if t := r.MCPTarget; t != nil {
		if a := t.Auth; a != nil {
			add(a.Value, "mcp_target", "auth", "value")
			add(a.ClientSecret, "mcp_target", "auth", "client_secret")
		}
		for k, v := range t.Headers {
			add(v, "mcp_target", "headers", k)
		}
	}
	if t := r.A2ATarget; t != nil {
		if a := t.Auth; a != nil {
			add(a.Value, "a2a_target", "auth", "value")
			add(a.ClientSecret, "a2a_target", "auth", "client_secret")
		}
		for k, v := range t.Headers {
			add(v, "a2a_target", "headers", k)
		}
		for _, s := range cloudAuthSlots(t.CloudAuth) {
			add(s.value, s.path...)
		}
	}
	return out
}

// cloudAuthSlots lists the credential fields of an A2A cloud_auth with their
// values, reference-shaped or not.
func cloudAuthSlots(c *registry.A2ACloudAuth) []slot {
	if c == nil {
		return nil
	}
	var out []slot
	add := func(value string, path ...string) {
		out = append(out, slot{path: append([]string{"a2a_target", "cloud_auth"}, path...), value: value})
	}
	if w := c.AWS; w != nil {
		add(w.AccessKeyID, "aws", "access_key_id")
		add(w.SecretAccessKey, "aws", "secret_access_key")
		add(w.SessionToken, "aws", "session_token")
	}
	if z := c.Azure; z != nil {
		add(z.ClientSecret, "azure", "client_secret")
	}
	if g := c.GCP; g != nil {
		add(g.ServiceAccountJSON, "gcp", "service_account_json")
	}
	return out
}

// copyRegistry returns a copy of r whose credential-bearing parts are its
// own, so setting a slot never writes through to r. Everything else,
// unexported and json:"-" fields included, is shared or copied by value.
func copyRegistry(r *registry.Registry) *registry.Registry {
	c := *r
	if r.LLMTarget != nil {
		t := *r.LLMTarget
		if r.LLMTarget.Auth != nil {
			a := *r.LLMTarget.Auth
			if a.APIKey != nil {
				k := *a.APIKey
				a.APIKey = &k
			}
			if a.AWS != nil {
				w := *a.AWS
				a.AWS = &w
			}
			if a.Azure != nil {
				z := *a.Azure
				a.Azure = &z
			}
			if a.OAuth != nil {
				o := *a.OAuth
				a.OAuth = &o
			}
			if a.GCPServiceAccount != nil {
				s := *a.GCPServiceAccount
				a.GCPServiceAccount = &s
			}
			t.Auth = &a
		}
		if r.LLMTarget.ProviderOptions != nil {
			opts := make(map[string]any, len(r.LLMTarget.ProviderOptions))
			for k, v := range r.LLMTarget.ProviderOptions {
				opts[k] = v
			}
			switch headers := opts[headersKey].(type) {
			case map[string]any:
				copied := make(map[string]any, len(headers))
				for k, v := range headers {
					copied[k] = v
				}
				opts[headersKey] = copied
			case map[string]string:
				copied := make(map[string]string, len(headers))
				for k, v := range headers {
					copied[k] = v
				}
				opts[headersKey] = copied
			}
			t.ProviderOptions = opts
		}
		c.LLMTarget = &t
	}
	if r.MCPTarget != nil {
		t := *r.MCPTarget
		if r.MCPTarget.Auth != nil {
			a := *r.MCPTarget.Auth
			t.Auth = &a
		}
		if r.MCPTarget.Headers != nil {
			headers := make(map[string]string, len(r.MCPTarget.Headers))
			for k, v := range r.MCPTarget.Headers {
				headers[k] = v
			}
			t.Headers = headers
		}
		c.MCPTarget = &t
	}
	if r.A2ATarget != nil {
		t := *r.A2ATarget
		if r.A2ATarget.Auth != nil {
			a := *r.A2ATarget.Auth
			t.Auth = &a
		}
		if r.A2ATarget.Headers != nil {
			headers := make(map[string]string, len(r.A2ATarget.Headers))
			for k, v := range r.A2ATarget.Headers {
				headers[k] = v
			}
			t.Headers = headers
		}
		if ca := r.A2ATarget.CloudAuth; ca != nil {
			cc := *ca
			if ca.AWS != nil {
				w := *ca.AWS
				cc.AWS = &w
			}
			if ca.Azure != nil {
				z := *ca.Azure
				cc.Azure = &z
			}
			if ca.GCP != nil {
				g := *ca.GCP
				cc.GCP = &g
			}
			t.CloudAuth = &cc
		}
		c.A2ATarget = &t
	}
	return &c
}

// setSlot writes value at path of c, a copy from copyRegistry. path is one
// that registrySlots returned for the same registry.
func setSlot(c *registry.Registry, path []string, value string) {
	if len(path) == 3 && path[0] == "mcp_target" && path[1] == headersKey {
		c.MCPTarget.Headers[path[2]] = value
		return
	}
	if len(path) == 3 && path[0] == "a2a_target" && path[1] == headersKey {
		c.A2ATarget.Headers[path[2]] = value
		return
	}
	if len(path) == 4 && path[0] == "a2a_target" && path[1] == "cloud_auth" {
		setCloudAuthSlot(c.A2ATarget.CloudAuth, path[2], path[3], value)
		return
	}
	switch strings.Join(path[:min(len(path), 3)], ".") {
	case "llm_target.auth.api_key":
		switch path[3] {
		case "api_key":
			c.LLMTarget.Auth.APIKey.APIKey = value
		case "header_value":
			c.LLMTarget.Auth.APIKey.HeaderValue = value
		case "param_value":
			c.LLMTarget.Auth.APIKey.ParamValue = value
		}
	case "llm_target.auth.aws":
		switch path[3] {
		case "access_key_id":
			c.LLMTarget.Auth.AWS.AccessKeyID = value
		case "secret_access_key":
			c.LLMTarget.Auth.AWS.SecretAccessKey = value
		case "session_token":
			c.LLMTarget.Auth.AWS.SessionToken = value
		}
	case "llm_target.auth.azure":
		switch path[3] {
		case "api_key":
			c.LLMTarget.Auth.Azure.APIKey = value
		case "client_secret":
			c.LLMTarget.Auth.Azure.ClientSecret = value
		}
	case "llm_target.auth.oauth":
		switch path[3] {
		case "client_secret":
			c.LLMTarget.Auth.OAuth.ClientSecret = value
		case "refresh_token":
			c.LLMTarget.Auth.OAuth.RefreshToken = value
		case "password":
			c.LLMTarget.Auth.OAuth.Password = value
		}
	case "llm_target.auth.gcp_service_account":
		*c.LLMTarget.Auth.GCPServiceAccount = value
	case "llm_target.provider_options.headers":
		switch headers := c.LLMTarget.ProviderOptions[headersKey].(type) {
		case map[string]any:
			headers[path[3]] = value
		case map[string]string:
			headers[path[3]] = value
		}
	case "mcp_target.auth.value":
		c.MCPTarget.Auth.Value = value
	case "mcp_target.auth.client_secret":
		c.MCPTarget.Auth.ClientSecret = value
	case "a2a_target.auth.value":
		c.A2ATarget.Auth.Value = value
	case "a2a_target.auth.client_secret":
		c.A2ATarget.Auth.ClientSecret = value
	}
}

func setCloudAuthSlot(c *registry.A2ACloudAuth, cloud, field, value string) {
	switch cloud + "." + field {
	case "aws.access_key_id":
		c.AWS.AccessKeyID = value
	case "aws.secret_access_key":
		c.AWS.SecretAccessKey = value
	case "aws.session_token":
		c.AWS.SessionToken = value
	case "azure.client_secret":
		c.Azure.ClientSecret = value
	case "gcp.service_account_json":
		c.GCP.ServiceAccountJSON = value
	}
}

// Use is a declared location of an entity and the reference-shaped value it
// holds.
type Use struct {
	Path []string
	Raw  string
	// Hosts are where the entity sends the value; empty when that cannot be
	// told, which a store with allowed destinations refuses.
	Hosts []string
	// SelfAddressed marks a value that names its own host, such as a
	// database DSN: no entity field can redirect it.
	SelfAddressed bool
}

// RegistryReferences lists the declared locations of r that hold a
// reference, and the paths of those that embed one inside a longer value,
// such as "Bearer secret://…", which is refused: only a whole value can be a
// reference.
func RegistryReferences(r *registry.Registry) (uses []Use, embedded []Use) {
	if r == nil {
		return nil, nil
	}
	for _, s := range registrySlots(r) {
		uses = append(uses, Use{Path: s.path, Raw: s.value, Hosts: s.hosts})
	}
	for _, s := range registryEmbedded(r) {
		embedded = append(embedded, Use{Path: s.path, Raw: s.value})
	}
	return uses, embedded
}

// registryEmbedded lists declared locations whose value contains the scheme
// without being a reference.
func registryEmbedded(r *registry.Registry) []slot {
	var out []slot
	visit := func(value string, path ...string) {
		if !domain.IsRef(value) && domain.ContainsRef(value) {
			out = append(out, slot{path: path, value: value})
		}
	}
	if t := r.LLMTarget; t != nil {
		if a := t.Auth; a != nil {
			if k := a.APIKey; k != nil {
				visit(k.APIKey, "llm_target", "auth", "api_key", "api_key")
				visit(k.HeaderValue, "llm_target", "auth", "api_key", "header_value")
				visit(k.ParamValue, "llm_target", "auth", "api_key", "param_value")
			}
			if w := a.AWS; w != nil {
				visit(w.AccessKeyID, "llm_target", "auth", "aws", "access_key_id")
				visit(w.SecretAccessKey, "llm_target", "auth", "aws", "secret_access_key")
				visit(w.SessionToken, "llm_target", "auth", "aws", "session_token")
			}
			if z := a.Azure; z != nil {
				visit(z.APIKey, "llm_target", "auth", "azure", "api_key")
				visit(z.ClientSecret, "llm_target", "auth", "azure", "client_secret")
			}
			if o := a.OAuth; o != nil {
				visit(o.ClientSecret, "llm_target", "auth", "oauth", "client_secret")
				visit(o.RefreshToken, "llm_target", "auth", "oauth", "refresh_token")
				visit(o.Password, "llm_target", "auth", "oauth", "password")
			}
			if a.GCPServiceAccount != nil {
				visit(*a.GCPServiceAccount, "llm_target", "auth", "gcp_service_account")
			}
		}
		switch headers := t.ProviderOptions[headersKey].(type) {
		case map[string]any:
			for k, v := range headers {
				if s, ok := v.(string); ok {
					visit(s, "llm_target", "provider_options", headersKey, k)
				}
			}
		case map[string]string:
			for k, v := range headers {
				visit(v, "llm_target", "provider_options", headersKey, k)
			}
		}
	}
	if t := r.MCPTarget; t != nil {
		if a := t.Auth; a != nil {
			visit(a.Value, "mcp_target", "auth", "value")
			visit(a.ClientSecret, "mcp_target", "auth", "client_secret")
		}
		for k, v := range t.Headers {
			visit(v, "mcp_target", headersKey, k)
		}
	}
	if t := r.A2ATarget; t != nil {
		if a := t.Auth; a != nil {
			visit(a.Value, "a2a_target", "auth", "value")
			visit(a.ClientSecret, "a2a_target", "auth", "client_secret")
		}
		for k, v := range t.Headers {
			visit(v, "a2a_target", headersKey, k)
		}
		for _, s := range cloudAuthSlots(t.CloudAuth) {
			visit(s.value, s.path...)
		}
	}
	return out
}

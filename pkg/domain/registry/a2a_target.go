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

package registry

import (
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/common/secret"
)

// A2AProtocolVersion is the A2A wire version a registry is pinned to.
type A2AProtocolVersion string

const (
	A2AVersion03 A2AProtocolVersion = "0.3"
	A2AVersion10 A2AProtocolVersion = "1.0"
)

// A2AAuthModeCloud signs an A2A call with the cloud credential in
// A2ATarget.CloudAuth. Only A2A registries accept it.
const A2AAuthModeCloud MCPAuthMode = "cloud"

// A2ACardAuth picks the credential that reads the agent card. Empty reads it
// anonymously on a generic agent, and with the registry's credential on a
// hosted one.
type A2ACardAuth string

const (
	A2ACardAuthSame              A2ACardAuth = "same"
	A2ACardAuthClientCredentials A2ACardAuth = "client_credentials"
	A2ACardAuthCloud             A2ACardAuth = "cloud"
)

var a2aMethods = map[A2AProtocolVersion][]string{
	A2AVersion03: {"message/send", "message/stream", "tasks/get", "tasks/cancel", "tasks/resubscribe"},
	A2AVersion10: {"SendMessage", "SendStreamingMessage", "GetTask", "CancelTask", "SubscribeToTask"},
}

var a2aReservedHeaders = []string{"Authorization", "Cookie", "Host", "Content-Length", "A2A-Version"}

// A2ATarget is the agent an A2A registry points at and the card pinned for it.
type A2ATarget struct {
	Provider          A2AProvider        `json:"provider,omitempty"`
	CardURL           string             `json:"card_url,omitempty"`
	ResolvedCardURL   string             `json:"resolved_card_url,omitempty"`
	ProtocolVersion   A2AProtocolVersion `json:"protocol_version,omitempty"`
	URL               string             `json:"url,omitempty"`
	BedrockAgentCore  *AgentCoreLocator  `json:"bedrock_agentcore,omitempty"`
	AzureFoundry      *FoundryLocator    `json:"azure_foundry,omitempty"`
	VertexAgentEngine *VertexLocator     `json:"vertex_agent_engine,omitempty"`
	Headers           map[string]string  `json:"headers,omitempty"`
	Auth              *MCPAuth           `json:"auth,omitempty"`
	CloudAuth         *A2ACloudAuth      `json:"cloud_auth,omitempty"`
	CardAuth          A2ACardAuth        `json:"card_auth,omitempty"`
	AllowedMethods    []string           `json:"allowed_methods,omitempty"`
	Card              json.RawMessage    `json:"card,omitempty"`
	CardDigest        string             `json:"card_digest,omitempty"`
	CardPinnedAt      time.Time          `json:"card_pinned_at,omitzero"`
	// UnreadableHeaders names the static headers read from storage whose value
	// could not be decrypted and was returned empty. Never serialised.
	UnreadableHeaders []string `json:"-"`
}

// Normalize fills the defaults: the generic provider, auth mode none, the
// DEFAULT AgentCore qualifier and the Foundry OBO scope. The actor of an
// exchange is always the calling application, so a stored one is dropped.
func (t *A2ATarget) Normalize() {
	if t == nil {
		return
	}
	if t.Provider == "" {
		t.Provider = A2AProviderGeneric
	}
	t.CardURL = strings.TrimSpace(t.CardURL)
	t.URL = strings.TrimSpace(t.URL)
	if t.Auth == nil {
		t.Auth = &MCPAuth{}
	}
	if t.Auth.Mode == "" {
		t.Auth.Mode = MCPAuthModeNone
	}
	t.Auth.Actor = ""
	if t.BedrockAgentCore != nil && t.BedrockAgentCore.Qualifier == "" {
		t.BedrockAgentCore.Qualifier = agentCoreDefaultQualifier
	}
	if t.Provider == A2AProviderAzureFoundry && t.Auth.Mode == MCPAuthModeExchange && t.Auth.Pattern == ExchangeOBO && t.Auth.Scope == "" {
		t.Auth.Scope = foundryOBOScope
	}
}

func (t *A2ATarget) locator() a2aLocator {
	switch {
	case t.Provider == A2AProviderBedrockAgentCore && t.BedrockAgentCore != nil:
		return t.BedrockAgentCore
	case t.Provider == A2AProviderAzureFoundry && t.AzureFoundry != nil:
		return t.AzureFoundry
	case t.Provider == A2AProviderVertexAgentEngine && t.VertexAgentEngine != nil:
		return t.VertexAgentEngine
	default:
		return nil
	}
}

// Endpoint is the URL the gateway calls: the one derived from a hosted
// agent's locator, else the url override, else the card's interface for the
// pinned version.
func (t *A2ATarget) Endpoint() string {
	if l := t.locator(); l != nil {
		return l.endpoint()
	}
	if t.URL != "" {
		return t.URL
	}
	return InterfaceURL(t.Card, t.ProtocolVersion)
}

// CardLocation is the URL the card is read from: the one derived from a hosted
// agent's locator for the pinned version (Foundry defaults to 1.0), else the
// resolved card URL once pinned, else card_url.
func (t *A2ATarget) CardLocation() string {
	if l := t.locator(); l != nil {
		return l.cardURL(t.ProtocolVersion)
	}
	if t.ResolvedCardURL != "" {
		return t.ResolvedCardURL
	}
	return t.CardURL
}

// OfferedVersions returns the versions the agent offers: both for Foundry,
// 0.3 for Vertex, and what the card declares otherwise.
func (t *A2ATarget) OfferedVersions(card []byte) []A2AProtocolVersion {
	switch t.Provider {
	case A2AProviderAzureFoundry:
		return []A2AProtocolVersion{A2AVersion03, A2AVersion10}
	case A2AProviderVertexAgentEngine:
		return []A2AProtocolVersion{A2AVersion03}
	default:
		return DetectVersions(card)
	}
}

// Pin validates card read from resolvedURL, settles the protocol version (the
// default the agent offers when none is set) and records the card as pinned.
// Nothing changes when it fails.
func (t *A2ATarget) Pin(resolvedURL string, card []byte, now time.Time) error {
	if err := ValidateCard(card); err != nil {
		return err
	}
	digest, err := CardDigest(card)
	if err != nil {
		return err
	}
	versions := t.OfferedVersions(card)
	pinned := *t
	if pinned.ProtocolVersion == "" {
		pinned.ProtocolVersion = DefaultVersion(versions)
	}
	if pinned.ProtocolVersion == "" || !slices.Contains(versions, pinned.ProtocolVersion) {
		offered, _ := json.Marshal(nonNilVersions(versions))
		return fmt.Errorf("%w: the agent card offers %s", ErrAgentVersionUnsupported, offered)
	}
	pinned.ResolvedCardURL = resolvedURL
	pinned.Card = card
	pinned.CardDigest = digest
	pinned.CardPinnedAt = now.UTC()
	if pinned.CardAuth == A2ACardAuthSame && hostOf(pinned.Endpoint()) != hostOf(resolvedURL) {
		return fmt.Errorf("%w: card_auth same sends the credential only to the agent's own host; the card is on %s and the endpoint on %s",
			ErrInvalidRegistry, hostOf(resolvedURL), hostOf(pinned.Endpoint()))
	}
	*t = pinned
	return nil
}

func nonNilVersions(v []A2AProtocolVersion) []A2AProtocolVersion {
	if v == nil {
		return []A2AProtocolVersion{}
	}
	return v
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Host)
}

func isHTTPSURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Host != ""
}

// Validate checks the provider and its locator, the headers, the auth mode
// the provider accepts, the card and cloud credentials, and the allowed
// methods of the pinned version.
func (t *A2ATarget) Validate() error {
	if t == nil {
		return fmt.Errorf("%w: a2a_target is required for A2A registries", ErrInvalidRegistry)
	}
	if err := t.validateLocation(); err != nil {
		return err
	}
	if v := t.ProtocolVersion; v != "" && v != A2AVersion03 && v != A2AVersion10 {
		return fmt.Errorf("%w: protocol_version must be \"0.3\" or \"1.0\"", ErrInvalidRegistry)
	}
	if t.Provider == A2AProviderVertexAgentEngine && t.ProtocolVersion == A2AVersion10 {
		return fmt.Errorf("%w: a Vertex AI agent speaks A2A 0.3", ErrAgentVersionUnsupported)
	}
	for name := range t.Headers {
		if slices.ContainsFunc(a2aReservedHeaders, func(r string) bool { return strings.EqualFold(r, name) }) ||
			strings.HasPrefix(strings.ToUpper(name), "X-AG-") {
			return fmt.Errorf("%w: header %q is reserved and cannot be sent to an agent", ErrInvalidRegistry, name)
		}
	}
	if name, masked := maskedHeader(t.Headers); masked {
		return fmt.Errorf("%w: header %q looks masked; send the full value or the masked value unchanged", ErrInvalidRegistry, name)
	}
	if err := t.validateAuth(); err != nil {
		return err
	}
	if err := t.validateCardAuth(); err != nil {
		return err
	}
	if err := t.validateCloudAuth(); err != nil {
		return err
	}
	for _, m := range t.AllowedMethods {
		if t.ProtocolVersion != "" && !slices.Contains(a2aMethods[t.ProtocolVersion], m) {
			return fmt.Errorf("%w: allowed_methods: %q is not a forwarded method of A2A %s", ErrInvalidRegistry, m, t.ProtocolVersion)
		}
	}
	return nil
}

func (t *A2ATarget) validateLocation() error {
	locators := 0
	for _, set := range []bool{t.BedrockAgentCore != nil, t.AzureFoundry != nil, t.VertexAgentEngine != nil} {
		if set {
			locators++
		}
	}
	switch t.Provider {
	case A2AProviderGeneric:
		if locators > 0 {
			return fmt.Errorf("%w: %s", ErrInvalidRegistry, t.Provider.locatedBy())
		}
		if !isHTTPURL(t.CardURL) {
			return fmt.Errorf("%w: card_url must be a valid http(s) URL", ErrInvalidRegistry)
		}
		if t.URL != "" && !isHTTPSURL(t.URL) {
			return fmt.Errorf("%w: url must be an https URL", ErrInvalidRegistry)
		}
		return nil
	case A2AProviderBedrockAgentCore, A2AProviderAzureFoundry, A2AProviderVertexAgentEngine:
		l := t.locator()
		if t.CardURL != "" || t.URL != "" || l == nil || locators != 1 {
			return fmt.Errorf("%w: %s, not by card_url or url", ErrInvalidRegistry, t.Provider.locatedBy())
		}
		return l.validate()
	default:
		return fmt.Errorf("%w: unknown provider %q", ErrInvalidRegistry, t.Provider)
	}
}

func (t *A2ATarget) validateAuth() error {
	a := t.Auth
	switch {
	case a.Mode == MCPAuthModePassthrough || a.Mode == MCPAuthModeForwarded:
		return fmt.Errorf("%w: auth mode %q is not supported on an agent: the caller's own credential never reaches an agent",
			ErrInvalidRegistry, a.Mode)
	case a.Mode == MCPAuthModeExchange && a.Pattern == ExchangeImpersonation:
		return fmt.Errorf("%w: exchange/impersonation is not supported on an agent: the agent must know which application acts",
			ErrInvalidRegistry)
	case !t.Provider.allowsAuth(a):
		return t.Provider.authError()
	}
	switch a.Mode {
	case A2AAuthModeCloud:
		if a.Header != "" || a.Value != "" {
			return fmt.Errorf("%w: auth mode cloud does not accept header/value", ErrInvalidRegistry)
		}
		return nil
	case MCPAuthModeExchange:
		switch a.Pattern {
		case ExchangeDelegation, ExchangeTokenExchange:
		case ExchangeOBO:
			if strings.TrimSpace(a.Scope) == "" {
				return fmt.Errorf("%w: exchange/obo requires scope (e.g. resource/.default)", ErrInvalidRegistry)
			}
		default:
			return fmt.Errorf("%w: exchange requires pattern (delegation|obo|token_exchange)", ErrInvalidRegistry)
		}
		return a.validateIdentityID()
	default:
		return a.Validate()
	}
}

func (t *A2ATarget) validateCardAuth() error {
	userToken := t.Auth.UsesIdPClient()
	switch {
	case t.CardAuth == "":
		if userToken && t.Provider == A2AProviderBedrockAgentCore {
			return fmt.Errorf("%w: reading the card needs an application credential when auth is exchange: "+
				"set card_auth client_credentials with client_id, client_secret and token_url", ErrInvalidRegistry)
		}
		if userToken && t.Provider == A2AProviderAzureFoundry {
			return fmt.Errorf("%w: reading the card needs an application credential when auth is exchange: "+
				"set card_auth cloud with cloud_auth.azure", ErrInvalidRegistry)
		}
		return nil
	case t.CardAuth == A2ACardAuthSame && t.Provider == A2AProviderGeneric:
		if t.Auth.Mode != MCPAuthModeStatic && t.Auth.Mode != MCPAuthModeClientCredentials {
			return fmt.Errorf("%w: card_auth same needs auth mode static or client_credentials", ErrInvalidRegistry)
		}
		if !isHTTPSURL(t.CardURL) {
			return fmt.Errorf("%w: card_auth same sends the credential only over https", ErrInvalidRegistry)
		}
		return nil
	case t.CardAuth == A2ACardAuthClientCredentials && t.Provider == A2AProviderBedrockAgentCore && userToken:
		a := t.Auth
		if strings.TrimSpace(a.ClientID) == "" || (a.ClientSecret == "" && !a.SecretUnreadable) || !isHTTPURL(a.TokenURL) {
			return fmt.Errorf("%w: card_auth client_credentials needs auth.client_id, auth.client_secret and an http(s) auth.token_url",
				ErrInvalidRegistry)
		}
		if secret.IsMasked(a.ClientSecret) {
			return fmt.Errorf("%w: secret cannot be a masked value; omit the field to keep the stored value", ErrInvalidRegistry)
		}
		return nil
	case t.CardAuth == A2ACardAuthCloud && t.Provider == A2AProviderAzureFoundry && userToken:
		return nil
	default:
		return fmt.Errorf("%w: card_auth %q is not valid for provider %s with auth mode %s",
			ErrInvalidRegistry, t.CardAuth, t.Provider, t.Auth.Mode)
	}
}

func (t *A2ATarget) validateCloudAuth() error {
	if t.Auth.Mode != A2AAuthModeCloud && t.CardAuth != A2ACardAuthCloud {
		if t.CloudAuth != nil {
			return fmt.Errorf("%w: cloud_auth is only valid with auth mode cloud or card_auth cloud", ErrInvalidRegistry)
		}
		return nil
	}
	if t.CloudAuth == nil || t.CloudAuth.kind() != t.Provider.cloudKind() {
		return t.Provider.cloudError()
	}
	return t.CloudAuth.validate()
}

// ValidateSharedDataPlane adds the rules of a gateway served by the shared
// SaaS data plane. The gateway's own cloud identity is never a tenant's
// credential there, so cloud_auth must carry one the tenant supplies: AWS
// static keys, or a role with the external id its trust policy requires; an
// Azure service principal; a GCP service-account key. Ambient credentials (the
// AWS default chain, Azure managed identity, GCP Application Default
// Credentials and GCP impersonation) are refused.
func (t *A2ATarget) ValidateSharedDataPlane() error {
	if t == nil || t.CloudAuth == nil {
		return nil
	}
	c := t.CloudAuth
	if c.AWS != nil {
		if err := c.AWS.validateSharedDataPlane(); err != nil {
			return err
		}
	}
	if c.Azure != nil && (c.Azure.UseManagedIdentity || !c.Azure.hasClientSecretCredential()) {
		return fmt.Errorf("%w: cloud_auth.azure must use a service principal (tenant_id, client_id, client_secret); "+
			"managed identity is not available on the shared data plane", ErrInvalidRegistry)
	}
	if c.GCP != nil {
		if c.GCP.ImpersonateServiceAccount != "" {
			return fmt.Errorf("%w: cloud_auth.gcp.impersonate_service_account is not available on the shared data plane: "+
				"provide service_account_json", ErrInvalidRegistry)
		}
		if strings.TrimSpace(c.GCP.ServiceAccountJSON) == "" {
			return fmt.Errorf("%w: cloud_auth.gcp.service_account_json is required on the shared data plane", ErrInvalidRegistry)
		}
	}
	return nil
}

// ResolveSecretsFrom keeps the stored credentials an update left blank or sent
// back masked: static headers, the auth secret of an unchanged mode, and the
// cloud secrets of an unchanged credential.
func (t *A2ATarget) ResolveSecretsFrom(prev *A2ATarget) {
	if t == nil || prev == nil {
		return
	}
	t.Headers, t.UnreadableHeaders = resolveHeaders(t.Headers, prev.Headers, prev.UnreadableHeaders)
	if t.Auth != nil && prev.Auth != nil && t.Auth.Mode == prev.Auth.Mode {
		switch t.Auth.Mode {
		case MCPAuthModeStatic:
			t.Auth.Value = secret.Resolve(t.Auth.Value, prev.Auth.Value)
			t.Auth.SecretUnreadable = t.Auth.Value == "" && prev.Auth.SecretUnreadable
		case MCPAuthModeClientCredentials, MCPAuthModeExchange:
			t.Auth.ClientSecret = secret.Resolve(t.Auth.ClientSecret, prev.Auth.ClientSecret)
			t.Auth.SecretUnreadable = t.Auth.ClientSecret == "" && prev.Auth.SecretUnreadable
		}
	}
	t.CloudAuth.resolveSecretsFrom(prev.CloudAuth)
}

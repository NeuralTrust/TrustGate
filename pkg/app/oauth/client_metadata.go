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

package oauth

import (
	"net/url"
	"strings"
)

// ClientMetadataPathPrefix is where the gateway publishes an OAuth Client ID
// Metadata Document for each upstream provider it connects to
// (draft-ietf-oauth-client-id-metadata-document, the MCP 2025-11-25
// registration method). An authorization server that advertises
// client_id_metadata_document_supported and no registration_endpoint (Aircall)
// takes the document's URL as the client_id and fetches it to learn the
// client's name and redirect URI. Nothing is registered upstream, so there is
// no secret: the client is public and the grant is bound by PKCE.
//
// The document lists exactly one redirect URI, connectCallbackURL(base,
// provider), so it is published per provider: {base}/oauth/client-metadata/{provider}.
const ClientMetadataPathPrefix = "/oauth/client-metadata/"

// connectCallbackPathPrefix is the connect redirect_uri path before the
// provider id.
const connectCallbackPathPrefix = "/oauth/callback/"

// ClientMetadataDocument is the client metadata the gateway publishes at its
// client_id URL. The authorization server reads it in place of a registration
// request, so it carries the fields that request would: one redirect URI, the
// authorization-code and refresh grants, and no client authentication.
type ClientMetadataDocument struct {
	ClientID                string   `json:"client_id"`
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

// NewClientMetadataDocument is the document published at
// {baseURL}/oauth/client-metadata/{provider}. ok is false for a provider id the
// document URL cannot carry as written (see metadataDocumentProvider): the
// client_id must be the exact URL the authorization server fetched.
func NewClientMetadataDocument(baseURL, provider, clientName string) (ClientMetadataDocument, bool) {
	baseURL = strings.TrimRight(baseURL, "/")
	if baseURL == "" || !metadataDocumentProvider(provider) {
		return ClientMetadataDocument{}, false
	}
	return ClientMetadataDocument{
		ClientID:                baseURL + ClientMetadataPathPrefix + provider,
		ClientName:              clientName,
		RedirectURIs:            []string{connectCallbackURL(baseURL, provider)},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
	}, true
}

// ClientMetadataURLForRedirect is the client_id URL of the published document
// that lists redirectURI, a connect callback {base}/oauth/callback/{provider}.
// ok is false for any other redirect URI, an http base (the draft requires an
// https client_id), or a provider id the URL cannot carry as written.
func ClientMetadataURLForRedirect(redirectURI string) (string, bool) {
	u, err := url.Parse(redirectURI)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil ||
		u.RawPath != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", false
	}
	provider, found := strings.CutPrefix(u.Path, connectCallbackPathPrefix)
	if !found || !metadataDocumentProvider(provider) {
		return "", false
	}
	return "https://" + u.Host + ClientMetadataPathPrefix + provider, true
}

// metadataDocumentProvider reports whether provider can be written into the
// document URL unescaped: catalog codes ("io.aircall/mcp") and slugs. Anything
// else (a space, '%', '?', '#') would make the URL the server fetches differ
// from the client_id the document states, or name a different resource.
func metadataDocumentProvider(provider string) bool {
	if provider == "" || strings.HasPrefix(provider, "/") || strings.HasSuffix(provider, "/") || strings.Contains(provider, "//") {
		return false
	}
	for _, c := range provider {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.', c == '-', c == '_', c == '~', c == '/':
		default:
			return false
		}
	}
	for _, segment := range strings.Split(provider, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

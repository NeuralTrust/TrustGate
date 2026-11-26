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

package trustguard

import (
	"encoding/json"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/common/requestmeta"
	"github.com/NeuralTrust/TrustGate/pkg/domain/bedrocknative"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

const (
	// The service answering /v2 is TrustGuard, so the peer stays "trustguard"; the span says which engine.
	v2EvaluateSpanName = "trustguard_v2.evaluate"
)

// v2Request is TrustGuard v2's evaluate body. TrustGuard v2 decodes it strictly and refuses
// application_id, attributes.application, attributes.model, attributes.user and
// attributes.mcp_server: the agent, model, user and MCP server are named only in assets.
type v2Request struct {
	OriginalRequest *requestmeta.OriginalRequest `json:"original_request,omitempty"`
	Payload         json.RawMessage              `json:"payload"`
	Direction       string                       `json:"direction"`
	Protocol        string                       `json:"protocol"`
	GatewayID       string                       `json:"gateway_id"`
	SessionID       string                       `json:"session_id,omitempty"`
	Assets          *v2Assets                    `json:"assets,omitempty"`
	Attributes      v2Attributes                 `json:"attributes"`
}

// v2Assets is what the request is about, one entry per kind.
type v2Assets struct {
	Agent     *v2Agent     `json:"agent,omitempty"`
	Model     *v2Model     `json:"model,omitempty"`
	User      *v2User      `json:"user,omitempty"`
	MCPServer *v2MCPServer `json:"mcp_server,omitempty"`
}

// v2Attributes keeps what is not an asset.
type v2Attributes struct {
	ContentType string       `json:"content_type"`
	Stream      *GuardStream `json:"stream,omitempty"`
	// ToolCall is the agent's id for the tool call being checked.
	ToolCall *GuardToolCall `json:"tool,omitempty"`
}

// v2Agent is the calling application: a consumer, or the synthetic one of a personal key
// or the MCP Store.
type v2Agent struct {
	ID        string `json:"id,omitempty"`
	Name      string `json:"name,omitempty"`
	Audience  string `json:"audience,omitempty"`
	Synthetic bool   `json:"synthetic,omitempty"`
}

// v2User is the end user. AuthMethod is the gateway's principal method (jwt, oauth, personal_key, api_key...): how it
// authenticated the user, which TrustGuard v2 reads to decide whether the email is vouched for.
type v2User struct {
	ID         string `json:"id,omitempty"`
	Email      string `json:"email,omitempty"`
	AuthMethod string `json:"auth_method,omitempty"`
	// Token is the end user's ID token; TrustGuard verifies it against the integration's identity provider
	// and takes the user from its claims.
	Token string `json:"token,omitempty"`
}

// v2MCPServer carries TrustGuard v2's canonical id of the server: the catalog code, or
// the registry id of a server added by URL.
type v2MCPServer struct {
	ID   string  `json:"id"`
	Name string  `json:"name,omitempty"`
	Tool *v2Tool `json:"tool,omitempty"`
}

type v2Tool struct {
	Name string `json:"name"`
}

type v2Model struct {
	Name          string `json:"name,omitempty"`
	Provider      string `json:"provider,omitempty"`
	RequestedName string `json:"requested_name,omitempty"`
}

func toV2Request(body GuardRequest, request *infracontext.RequestContext) v2Request {
	req := v2Request{
		OriginalRequest: body.OriginalRequest,
		Payload:         append(json.RawMessage(nil), body.Payload...),
		Direction:       body.Direction,
		Protocol:        body.Protocol,
		GatewayID:       body.GatewayID,
		SessionID:       body.SessionID,
		Attributes: v2Attributes{
			ContentType: body.Attributes.ContentType,
			Stream:      body.Attributes.Stream,
		},
	}
	assets := v2Assets{
		Agent:     v2AgentOf(body),
		User:      v2UserOf(body.Attributes.User),
		MCPServer: v2MCPServerOf(body.Attributes.MCPServer),
	}
	if request != nil {
		// An A2A call names an agent, not a model: the agent is assets.agent.
		if !request.MCP && !request.A2A {
			assets.Model = v2ModelOf(request, body.Direction)
		} else if server := assets.MCPServer; server != nil {
			server.Name = strings.TrimSpace(request.MCPServerName)
			if tool := strings.TrimSpace(request.MCPTool); tool != "" {
				server.Tool = &v2Tool{Name: tool}
			}
		}
		req.Attributes.ToolCall = toolCallOf(request)
	}
	if body.UserToken != "" {
		// With no principal the token is the whole user: TrustGuard takes it from the claims.
		if assets.User == nil {
			assets.User = &v2User{}
		}
		assets.User.Token = body.UserToken
	}
	if assets != (v2Assets{}) {
		req.Assets = &assets
	}
	return req
}

func v2AgentOf(body GuardRequest) *v2Agent {
	agent := v2Agent{ID: strings.TrimSpace(body.ConsumerID)}
	if c := body.Attributes.Consumer; c != nil {
		agent.Name = c.Name
		agent.Audience = c.Audience
		agent.Synthetic = c.Synthetic
	}
	if agent == (v2Agent{}) {
		return nil
	}
	return &agent
}

func v2UserOf(user *GuardUser) *v2User {
	if user == nil || *user == (GuardUser{}) {
		return nil
	}
	return &v2User{ID: user.ID, Email: user.Email, AuthMethod: user.AuthMethod}
}

// withInventory adds to a v1-shaped body what TrustGuard v2's inventory needs once the
// collector's organisation is cut over: the model the upstream was sent and, for a tools/call,
// the server's name and the native tool. They ride inside attributes, which TrustGuard v1 reads
// as a free map, so a v1 answer is unchanged; TrustGuard maps them onto v2's names when v2
// answers. The pointers of body are not shared with the caller's copy.
func withInventory(body GuardRequest) GuardRequest {
	req := body.request
	if req == nil {
		return body
	}
	if !req.MCP {
		if served := v2ModelOf(req, body.Direction); served != nil && served.Name != "" {
			body.Attributes.Model.ServedName = served.Name
		}
		return body
	}
	if body.Attributes.MCPServer != nil {
		server := *body.Attributes.MCPServer
		server.Name = strings.TrimSpace(req.MCPServerName)
		if tool := strings.TrimSpace(req.MCPTool); tool != "" {
			server.Tool = &GuardTool{Name: tool}
		}
		body.Attributes.MCPServer = &server
	}
	body.Attributes.ToolCall = toolCallOf(req)
	return body
}

func v2ModelOf(req *infracontext.RequestContext, direction string) *v2Model {
	name := strings.TrimSpace(req.ResolvedModel)
	if name == "" && direction == directionOutput {
		name = strings.TrimSpace(req.SentModel)
	}
	if name == "" {
		if req.IsBedrockNative() {
			name = req.BedrockNative.ModelID
		} else {
			if model, err := adapter.ExtractModel(req.Body); err == nil {
				name = model
			}
			if name == "" {
				name = req.DefaultModel
			}
		}
	}
	name = strings.TrimSpace(name)
	if arn, ok := bedrocknative.ParseBedrockARN(name); ok {
		name, _ = arn.ModelID()
	}
	if strings.Contains(name, "@") || strings.HasPrefix(strings.ToLower(name), "pool:") ||
		strings.HasPrefix(strings.ToLower(name), "arn:") || strings.EqualFold(name, "auto") {
		name = ""
	}
	model := v2Model{
		Name:          name,
		Provider:      strings.ToLower(strings.TrimSpace(req.Provider)),
		RequestedName: strings.TrimSpace(req.RequestedModel),
	}
	if model == (v2Model{}) {
		return nil
	}
	return &model
}

func v2MCPServerOf(server *GuardMCPServer) *v2MCPServer {
	if server == nil {
		return nil
	}
	id := server.ID
	if server.Code != "" {
		id = server.Code
	}
	if id == "" {
		return nil
	}
	return &v2MCPServer{ID: id}
}

// normalizeV2Response reads a v2-shaped /v1/evaluate answer in the v1 shape the plugin enforces. The v2
// statuses are v1's (allow, report, skip, transform, ask, block); only the findings name their
// source differently, so the ids a finding is deduplicated by are filled from the v2 ones.
// The control's name is not copied to detector_name: that one reaches the client's block message.
func normalizeV2Response(resp *GuardResponse) {
	if resp == nil {
		return
	}
	for i := range resp.Findings {
		src := resp.Findings[i].Source
		if src == nil || src.DetectorID != "" {
			continue
		}
		switch {
		case src.ControlID != "":
			src.DetectorID = src.ControlID
		case src.ExceptionID != "":
			src.DetectorID = src.ExceptionID
		case src.AssetID != "":
			src.DetectorID = src.AssetID
		}
	}
}

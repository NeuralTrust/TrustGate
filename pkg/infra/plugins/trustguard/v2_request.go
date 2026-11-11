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

// v2Request is TrustGuard v2's evaluate body. TrustGuard v2 decodes it strictly and knows no
// v2 name: consumer_id is application_id, and there is no a2a.
type v2Request struct {
	OriginalRequest *requestmeta.OriginalRequest `json:"original_request,omitempty"`
	Payload         json.RawMessage              `json:"payload"`
	Direction       string                       `json:"direction"`
	Protocol        string                       `json:"protocol"`
	GatewayID       string                       `json:"gateway_id"`
	SessionID       string                       `json:"session_id,omitempty"`
	ApplicationID   string                       `json:"application_id,omitempty"`
	Attributes      v2Attributes                 `json:"attributes"`
}

type v2Attributes struct {
	ContentType string         `json:"content_type"`
	Model       *v2Model       `json:"model,omitempty"`
	User        *GuardUser     `json:"user,omitempty"`
	Application *v2Application `json:"application,omitempty"`
	MCPServer   *v2MCPServer   `json:"mcp_server,omitempty"`
	Stream      *GuardStream   `json:"stream,omitempty"`
}

// v2Application describes the consumer a request came from. Audience and Synthetic tell
// TrustGuard v2 not to inventory a personal key or the MCP Store as an application.
type v2Application struct {
	Name      string `json:"name,omitempty"`
	Audience  string `json:"audience,omitempty"`
	Synthetic bool   `json:"synthetic,omitempty"`
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
		ApplicationID:   strings.TrimSpace(body.ConsumerID),
		Attributes: v2Attributes{
			ContentType: body.Attributes.ContentType,
			User:        body.Attributes.User,
			MCPServer:   v2MCPServerOf(body.Attributes.MCPServer),
			Stream:      body.Attributes.Stream,
		},
	}
	if request != nil {
		if !request.MCP {
			req.Attributes.Model = v2ModelOf(request, body.Direction)
		} else if server := req.Attributes.MCPServer; server != nil {
			server.Name = strings.TrimSpace(request.MCPServerName)
			if tool := strings.TrimSpace(request.MCPTool); tool != "" {
				server.Tool = &v2Tool{Name: tool}
			}
		}
	}
	req.Attributes.Application = v2ApplicationOf(body.Attributes.Consumer)
	return req
}

func v2ApplicationOf(consumer *GuardConsumer) *v2Application {
	if consumer == nil {
		return nil
	}
	app := v2Application{Name: consumer.Name, Audience: consumer.Audience, Synthetic: consumer.Synthetic}
	if app == (v2Application{}) {
		return nil
	}
	return &app
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
		if served := v2ModelOf(req, body.Direction).Name; served != "" {
			body.Attributes.Model.ServedName = served
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
	return &v2Model{
		Name:          name,
		Provider:      strings.ToLower(strings.TrimSpace(req.Provider)),
		RequestedName: req.RequestedModel,
	}
}

func v2MCPServerOf(server *GuardMCPServer) *v2MCPServer {
	if server == nil {
		return nil
	}
	if server.Code != "" {
		return &v2MCPServer{ID: server.Code}
	}
	return &v2MCPServer{ID: server.ID}
}

// normalizeV2Response reads a /v2/evaluate answer in the v1 shape the plugin enforces. The v2
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

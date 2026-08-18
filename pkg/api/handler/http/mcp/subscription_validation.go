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

package mcp

import (
	"encoding/json"
	"strings"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
)

const (
	mediaTypeEventStream             = "text/event-stream"
	mediaTypeJSON                    = "application/json"
	maxSubscriptionNotificationKinds = 3
)

// subscriptionListenHeaders enforces the listen-specific header contract. It is
// the inverse of the tasks/* binding: a lease addresses no single named object,
// so a Mcp-Name would describe nothing, and the response is two media types —
// SSE frames whose payloads are JSON — so both must be acceptable to the client
// before any authorization work is done.
func subscriptionListenHeaders(headers modernRequestHeaders) *protocolError {
	if headers.name != "" {
		return headerMismatch("Mcp-Name is not supported on " + appmcp.MethodSubscriptionsListen)
	}
	if !acceptsSubscriptionStream(headers.accept) {
		return headerMismatch("Accept must include " + mediaTypeEventStream + " and " + mediaTypeJSON)
	}
	return nil
}

// acceptsSubscriptionStream reports whether the Accept header names both media
// types the stream uses. A wildcard is not enough: the client has to prove it
// understands an event stream, otherwise it would be handed frames it will
// buffer to completion.
func acceptsSubscriptionStream(accept string) bool {
	var stream, payload bool
	for _, media := range acceptedMediaTypes(accept) {
		switch media {
		case mediaTypeEventStream:
			stream = true
		case mediaTypeJSON:
			payload = true
		}
	}
	return stream && payload
}

// acceptedMediaTypes is the lower-cased media types of an Accept header with
// their parameters stripped, in the order they were sent.
func acceptedMediaTypes(accept string) []string {
	parts := strings.Split(accept, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		media := part
		if idx := strings.IndexByte(media, ';'); idx >= 0 {
			media = media[:idx]
		}
		media = strings.ToLower(strings.TrimSpace(media))
		if media == "" {
			continue
		}
		out = append(out, media)
	}
	return out
}

// subscriptionListenParams is the validated shape of a listen request. The
// requested kinds are what the client asked for, not what will be honoured.
type subscriptionListenParams struct {
	requested appmcp.HonouredSet
}

// validateSubscriptionListenParams parses params.notifications and bounds
// params.resourceSubscriptions. Resource subscriptions are validated and then
// discarded: TrustGate never advertises resources.subscribe, so accepting the
// field silently would let a client believe a per-URI subscription exists.
func validateSubscriptionListenParams(
	raw json.RawMessage,
	maxURIs int,
) (subscriptionListenParams, *protocolError) {
	params, ok := decodeObject(raw)
	if !ok {
		return subscriptionListenParams{}, newProtocolError(codeInvalidParams, "params must be an object")
	}
	notificationsRaw, ok := params["notifications"]
	if !ok {
		return subscriptionListenParams{}, newProtocolError(
			codeInvalidParams,
			appmcp.MethodSubscriptionsListen+" requires params.notifications",
		)
	}
	var requested []string
	if err := json.Unmarshal(notificationsRaw, &requested); err != nil {
		return subscriptionListenParams{}, newProtocolError(
			codeInvalidParams,
			"params.notifications must be an array of notification types",
		)
	}
	if len(requested) > maxSubscriptionNotificationKinds {
		return subscriptionListenParams{}, newProtocolError(
			codeInvalidParams,
			"params.notifications exceeds the maximum number of notification types",
		)
	}
	if protocolErr := validateResourceSubscriptions(params["resourceSubscriptions"], maxURIs); protocolErr != nil {
		return subscriptionListenParams{}, protocolErr
	}

	kinds := make([]appmcp.NotificationKind, 0, len(requested))
	for _, raw := range requested {
		// An unknown type is dropped rather than refused: the honoured subset is
		// an intersection, and a client asking only for types TrustGate cannot
		// stream is answered by an empty ack, not by an error.
		if kind, ok := appmcp.BoundNotificationKind(raw); ok {
			kinds = append(kinds, kind)
		}
	}
	return subscriptionListenParams{requested: appmcp.NewHonouredSet(kinds...)}, nil
}

func validateResourceSubscriptions(raw json.RawMessage, maxURIs int) *protocolError {
	if len(raw) == 0 {
		return nil
	}
	var uris []string
	if err := json.Unmarshal(raw, &uris); err != nil {
		return newProtocolError(codeInvalidParams, "params.resourceSubscriptions must be an array of URIs")
	}
	if maxURIs > 0 && len(uris) > maxURIs {
		return newProtocolError(codeInvalidParams, "params.resourceSubscriptions exceeds the maximum number of URIs")
	}
	for _, uri := range uris {
		if uri == "" {
			return newProtocolError(codeInvalidParams, "params.resourceSubscriptions entries must be non-empty URIs")
		}
	}
	return nil
}

// notificationKindsByCapability maps each primitive kind discovery can advertise
// onto the one notification it produces. Membership is the whole allow-list on
// both sides: a kind absent here is neither advertised as listChanged nor
// honourable on a lease.
var notificationKindsByCapability = map[string]appmcp.NotificationKind{
	"tools":     appmcp.NotificationToolsListChanged,
	"prompts":   appmcp.NotificationPromptsListChanged,
	"resources": appmcp.NotificationResourcesListChanged,
}

// honouredSubset narrows the requested kinds to those this role-scoped consumer
// can actually see. The advertised capability set is the authority, so a kind the
// toolkit or the role scope denies is unhonourable however it was asked for, and
// the ack tells the client exactly that.
func honouredSubset(requested appmcp.HonouredSet, rc *appconsumer.RoutableConsumer) appmcp.HonouredSet {
	capabilities := configuredCapabilities(rc, false)
	visible := make([]appmcp.NotificationKind, 0, len(capabilities))
	for capability, kind := range notificationKindsByCapability {
		if _, ok := capabilities[capability]; ok {
			visible = append(visible, kind)
		}
	}
	return requested.Intersect(appmcp.NewHonouredSet(visible...))
}

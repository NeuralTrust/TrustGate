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

package client

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"time"

	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
)

const subscriptionRequestID = "trustgate-subscription"

type modernSubscriptionConnector struct {
	probe         protocolProbe
	transport     http.RoundTripper
	maxEventBytes int
	idleTimeout   time.Duration
}

// NewModernSubscriptionConnector creates the modern POST-only subscription adapter.
func NewModernSubscriptionConnector(
	maxEventBytes int,
	idleTimeout time.Duration,
) appmcp.SubscriptionConnector {
	return &modernSubscriptionConnector{
		probe:         newProtocolProbe(sharedHTTPTransport),
		transport:     sharedHTTPTransport,
		maxEventBytes: maxEventBytes,
		idleTimeout:   idleTimeout,
	}
}

func (c *modernSubscriptionConnector) Prepare(
	ctx context.Context,
	target appmcp.Target,
) (appmcp.PreparedSubscription, error) {
	capabilities, err := prepareModernSubscription(ctx, c.probe, target)
	if err != nil {
		return appmcp.PreparedSubscription{}, err
	}
	key, err := c.SourceKey(target, capabilities)
	if err != nil {
		return appmcp.PreparedSubscription{}, fmt.Errorf("%w: %v", appmcp.ErrSubscriptionProtocol, err)
	}
	return appmcp.PreparedSubscription{Key: key, Capabilities: capabilities}, nil
}

func (c *modernSubscriptionConnector) SourceKey(
	target appmcp.Target,
	capabilities appmcp.ListChangedCapabilities,
) (appmcp.SubscriptionSourceKey, error) {
	return subscriptionSourceKey(target, capabilities)
}

func (c *modernSubscriptionConnector) Open(
	ctx context.Context,
	target appmcp.Target,
	prepared appmcp.PreparedSubscription,
) (appmcp.SubscriptionStream, error) {
	if c.maxEventBytes <= 0 || c.idleTimeout <= 0 {
		return nil, fmt.Errorf("%w: invalid stream bounds", appmcp.ErrSubscriptionProtocol)
	}
	key, err := subscriptionSourceKey(target, prepared.Capabilities)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appmcp.ErrSubscriptionProtocol, err)
	}
	if key != prepared.Key || prepared.Capabilities.Empty() {
		return nil, appmcp.ErrSubscriptionSourceChanged
	}
	body, err := subscriptionListenBody(prepared.Capabilities)
	if err != nil {
		return nil, fmt.Errorf("%w: encode listen request: %v", appmcp.ErrSubscriptionProtocol, err)
	}
	client, err := newTargetHTTPClientWithTransport(target.Headers, c.transport)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appmcp.ErrSubscriptionProtocol, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.URL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%w: build listen request: %v", appmcp.ErrSubscriptionProtocol, err)
	}
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Mcp-Method", appmcp.MethodSubscriptionsListen)
	req.Header.Set("Mcp-Protocol-Version", modernProtocolVersion)
	resp, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("%w: %v", appmcp.ErrSubscriptionTransportClosed, err)
	}
	if err := validateSubscriptionResponse(resp); err != nil {
		resp.Body.Close()
		return nil, err
	}
	stream := &modernSubscriptionStream{
		body:          resp.Body,
		reader:        bufio.NewReaderSize(resp.Body, min(c.maxEventBytes+1, 64*1024)),
		acknowledged:  prepared.Capabilities,
		maxEventBytes: c.maxEventBytes,
		idleTimeout:   c.idleTimeout,
	}
	first, err := stream.nextMessage(ctx)
	if err != nil {
		stream.Close()
		return nil, err
	}
	acknowledged, err := decodeSubscriptionAcknowledgement(first)
	if err != nil {
		stream.Close()
		return nil, err
	}
	if !acknowledged.Equal(prepared.Capabilities) {
		stream.Close()
		return nil, appmcp.ErrSubscriptionSourceChanged
	}
	stream.acknowledged = acknowledged
	return stream, nil
}

func validateSubscriptionResponse(resp *http.Response) error {
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return appmcp.ErrSubscriptionAuthentication
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("%w: HTTP status %d", appmcp.ErrSubscriptionTerminal, resp.StatusCode)
	}
	contentType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || contentType != "text/event-stream" {
		return fmt.Errorf("%w: listen response is not text/event-stream", appmcp.ErrSubscriptionProtocol)
	}
	if resp.Header.Get("Mcp-Session-Id") != "" {
		return fmt.Errorf("%w: sessionful listen response", appmcp.ErrSubscriptionProtocol)
	}
	return nil
}

func subscriptionListenBody(capabilities appmcp.ListChangedCapabilities) ([]byte, error) {
	notifications := map[string]bool{
		string(appmcp.NotificationToolsListChanged):     capabilities.Tools,
		string(appmcp.NotificationPromptsListChanged):   capabilities.Prompts,
		string(appmcp.NotificationResourcesListChanged): capabilities.Resources,
	}
	return json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      subscriptionRequestID,
		"method":  appmcp.MethodSubscriptionsListen,
		"params": map[string]any{
			"notifications": notifications,
		},
	})
}

func subscriptionSourceKey(
	target appmcp.Target,
	capabilities appmcp.ListChangedCapabilities,
) (appmcp.SubscriptionSourceKey, error) {
	canonicalTarget, origin, err := canonicalSubscriptionTarget(target.URL)
	if err != nil {
		return appmcp.SubscriptionSourceKey{}, err
	}
	return appmcp.SubscriptionSourceKey{
		TargetDigest:          sha256.Sum256([]byte(canonicalTarget)),
		OriginDigest:          sha256.Sum256([]byte(origin)),
		RegistryTargetDigest:  sha256.Sum256([]byte(target.RegistryTargetID)),
		PinDigest:             sha256.Sum256([]byte(target.PinKey)),
		CredentialFingerprint: sha256.Sum256([]byte(credentialFingerprint(target.Headers))),
		ProtocolVersion:       modernProtocolVersion,
		Capabilities:          capabilities,
	}, nil
}

func canonicalSubscriptionTarget(rawURL string) (string, string, error) {
	origin, err := canonicalOrigin(rawURL)
	if err != nil {
		return "", "", err
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", "", err
	}
	originURL, err := url.Parse(origin)
	if err != nil {
		return "", "", err
	}
	parsed.Scheme = originURL.Scheme
	parsed.Host = originURL.Host
	if parsed.Path == "" {
		parsed.Path = "/"
	}
	return parsed.String(), origin, nil
}

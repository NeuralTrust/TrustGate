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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"

	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	"github.com/NeuralTrust/TrustGate/pkg/version"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
)

const (
	modernProtocolVersion = "2026-07-28"
	probeRequestID        = "trustgate-probe-1"
	maxProbeBodyBytes     = 64 * 1024

	metaProtocolVersion    = "io.modelcontextprotocol/protocolVersion"
	metaClientInfo         = "io.modelcontextprotocol/clientInfo"
	metaClientCapabilities = "io.modelcontextprotocol/clientCapabilities"
)

// legacyProtocolVersions are the pre-SEP-2575 versions the legacy adapter can
// negotiate through the initialize handshake, newest first.
var legacyProtocolVersions = []string{"2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}

var errProbeBodyTooLarge = errors.New("mcp probe response body exceeds 64 KiB")

type probeErrorCode string

const (
	probeErrorInvalidResponse            probeErrorCode = "invalid_response"
	probeErrorInvalidNegotiationRetry    probeErrorCode = "invalid_negotiation_retry"
	probeErrorMissingResult              probeErrorCode = "missing_result"
	probeErrorRPC                        probeErrorCode = "rpc_error"
	probeErrorUnexpectedBadRequestResult probeErrorCode = "unexpected_bad_request_result"
)

type probeClassificationError struct {
	code    probeErrorCode
	rpcCode int64
}

func (e *probeClassificationError) Error() string {
	switch e.code {
	case probeErrorInvalidResponse:
		return "mcp server/discover returned an invalid response"
	case probeErrorInvalidNegotiationRetry:
		return "mcp server/discover returned an invalid negotiation retry response"
	case probeErrorMissingResult:
		return "mcp server/discover response is missing a result"
	case probeErrorRPC:
		return fmt.Sprintf("mcp server/discover returned JSON-RPC error code %d", e.rpcCode)
	case probeErrorUnexpectedBadRequestResult:
		return "mcp server/discover returned a result with HTTP 400"
	default:
		return "mcp server/discover classification failed"
	}
}

func (e *probeClassificationError) Unwrap() error {
	return appmcp.ErrUnreachable
}

type probeKind uint8

const (
	probeUnknown probeKind = iota
	probeModern
	probeLegacyCandidate
	probeModernIncompatible
)

type probeOutcome struct {
	kind    probeKind
	version string
}

type strictProbe struct {
	transport             http.RoundTripper
	supportedVersions     []string
	legacyVersions        []string
	implementationVersion string
}

func newProtocolProbe(transport http.RoundTripper) *strictProbe {
	return newStrictProbe(transport, []string{modernProtocolVersion}, version.Version)
}

func newStrictProbe(transport http.RoundTripper, supportedVersions []string, implementationVersion string) *strictProbe {
	return &strictProbe{
		transport:             transport,
		supportedVersions:     append([]string(nil), supportedVersions...),
		legacyVersions:        append([]string(nil), legacyProtocolVersions...),
		implementationVersion: implementationVersion,
	}
}

func (p *strictProbe) Probe(ctx context.Context, target appmcp.Target) (probeOutcome, error) {
	client, err := newTargetHTTPClientWithTransport(target.Headers, p.transport)
	if err != nil {
		return probeOutcome{}, fmt.Errorf("%w: invalid upstream HTTP configuration: %w", appmcp.ErrUnreachable, err)
	}
	if len(p.supportedVersions) == 0 {
		return incompatibleProbeOutcome()
	}

	requested := p.supportedVersions[0]
	attempt, err := p.request(ctx, client, target.URL, requested)
	if err != nil {
		return probeOutcome{}, err
	}
	outcome, retryVersion, err := p.classify(attempt, requested, true)
	if err != nil || retryVersion == "" {
		return outcome, err
	}

	retry, err := p.request(ctx, client, target.URL, retryVersion)
	if err != nil {
		return probeOutcome{}, err
	}
	outcome, _, err = p.classify(retry, retryVersion, false)
	return outcome, err
}

type probeAttempt struct {
	status          int
	hasResultMember bool
	response        *jsonrpc.Response
	result          *discoverProbeResult
	parseErr        error
}

type discoverProbeResult struct {
	ResultType        string
	SupportedVersions []string
}

func (p *strictProbe) request(
	ctx context.Context,
	client *http.Client,
	endpoint string,
	protocolVersion string,
) (probeAttempt, error) {
	origin, err := canonicalOrigin(endpoint)
	if err != nil {
		return probeAttempt{}, wrapUnreachable("", "invalid upstream origin", err)
	}
	body, err := p.requestBody(protocolVersion)
	if err != nil {
		return probeAttempt{}, fmt.Errorf("encode server/discover probe: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return probeAttempt{}, wrapUnreachable(origin, "build probe request", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Protocol-Version", protocolVersion)
	req.Header.Set("Mcp-Method", "server/discover")
	req.Header.Set("User-Agent", "trustgate/"+p.implementationVersion)

	resp, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return probeAttempt{}, ctx.Err()
		}
		return probeAttempt{}, wrapUnreachable(origin, "probe request", err)
	}
	raw, readErr := readBoundedProbeBody(resp.Body)
	closeErr := resp.Body.Close()
	if ctx.Err() != nil {
		return probeAttempt{}, ctx.Err()
	}
	if readErr != nil {
		return probeAttempt{}, wrapUnreachable(origin, "read probe response", readErr)
	}
	if closeErr != nil {
		return probeAttempt{}, wrapUnreachable(origin, "close probe response", closeErr)
	}

	attempt := probeAttempt{status: resp.StatusCode}
	attempt.hasResultMember = hasTopLevelJSONMember(raw, "result")
	if len(bytes.TrimSpace(raw)) == 0 {
		attempt.parseErr = errors.New("empty probe response")
		return attempt, nil
	}
	message, hasResultMember, err := probeMessage(resp.Header.Get("Content-Type"), raw)
	attempt.hasResultMember = attempt.hasResultMember || hasResultMember
	if err != nil {
		attempt.parseErr = err
		return attempt, nil
	}
	attempt.response, attempt.result, attempt.parseErr = decodeDiscoverProbeResponse(message)
	return attempt, nil
}

func (p *strictProbe) requestBody(protocolVersion string) ([]byte, error) {
	id, err := jsonrpc.MakeID(probeRequestID)
	if err != nil {
		return nil, err
	}
	params, err := json.Marshal(map[string]any{
		"_meta": map[string]any{
			metaProtocolVersion: protocolVersion,
			metaClientInfo: map[string]string{
				"name":    "trustgate",
				"version": p.implementationVersion,
			},
			metaClientCapabilities: map[string]any{},
		},
	})
	if err != nil {
		return nil, err
	}
	return jsonrpc.EncodeMessage(&jsonrpc.Request{
		ID:     id,
		Method: "server/discover",
		Params: params,
	})
}

func (p *strictProbe) classify(
	attempt probeAttempt,
	requestedVersion string,
	allowRetry bool,
) (probeOutcome, string, error) {
	if attempt.status >= http.StatusOK && attempt.status < http.StatusMultipleChoices {
		return p.classifySuccess(attempt, requestedVersion, !allowRetry)
	}
	if attempt.status == http.StatusBadRequest && attempt.hasResultMember {
		return probeOutcome{}, "", &probeClassificationError{code: probeErrorUnexpectedBadRequestResult}
	}
	if attempt.status != http.StatusBadRequest {
		return probeOutcome{}, "", fmt.Errorf(
			"%w: server/discover returned HTTP status %d",
			appmcp.ErrUnreachable,
			attempt.status,
		)
	}
	if !allowRetry {
		if attempt.response != nil && attempt.response.Error != nil {
			if rpcErr, ok := probeRPCError(attempt.response.Error); ok && isModernProofRPCCode(rpcErr.Code) {
				outcome, err := incompatibleProbeOutcome()
				return outcome, "", err
			}
		}
		return probeOutcome{}, "", &probeClassificationError{code: probeErrorInvalidNegotiationRetry}
	}
	if attempt.parseErr != nil || attempt.response == nil || attempt.response.Error == nil {
		return probeOutcome{kind: probeLegacyCandidate}, "", nil
	}

	rpcErr, ok := probeRPCError(attempt.response.Error)
	if !ok {
		return probeOutcome{kind: probeLegacyCandidate}, "", nil
	}
	if !isModernProofRPCCode(rpcErr.Code) {
		return probeOutcome{kind: probeLegacyCandidate}, "", nil
	}
	switch rpcErr.Code {
	case codeHeaderMismatch, codeRequiredCapability:
		return probeOutcome{kind: probeModern, version: requestedVersion}, "", nil
	case codeUnsupportedProtocolVersion:
		advertised := supportedVersionsFromError(rpcErr)
		if retryVersion := latestMutuallySupported(p.supportedVersions, advertised); retryVersion != "" {
			return probeOutcome{}, retryVersion, nil
		}
		return p.downgrade(advertised)
	}
	return probeOutcome{kind: probeLegacyCandidate}, "", nil
}

func (p *strictProbe) classifySuccess(
	attempt probeAttempt,
	requestedVersion string,
	requireRequestedVersion bool,
) (probeOutcome, string, error) {
	if attempt.parseErr != nil || attempt.response == nil {
		return probeOutcome{}, "", &probeClassificationError{code: probeErrorInvalidResponse}
	}
	if attempt.response.Error != nil {
		rpcErr, ok := probeRPCError(attempt.response.Error)
		if !ok {
			return probeOutcome{}, "", &probeClassificationError{code: probeErrorRPC}
		}
		return probeOutcome{}, "", &probeClassificationError{code: probeErrorRPC, rpcCode: rpcErr.Code}
	}
	if attempt.result == nil {
		return probeOutcome{}, "", &probeClassificationError{code: probeErrorMissingResult}
	}
	if requireRequestedVersion {
		if latestMutuallySupported([]string{requestedVersion}, attempt.result.SupportedVersions) == "" {
			return p.downgrade(attempt.result.SupportedVersions)
		}
		return probeOutcome{kind: probeModern, version: requestedVersion}, "", nil
	}
	version := latestMutuallySupported(p.supportedVersions, attempt.result.SupportedVersions)
	if version == "" {
		return p.downgrade(attempt.result.SupportedVersions)
	}
	return probeOutcome{kind: probeModern, version: version}, "", nil
}

// downgrade classifies an upstream that answered server/discover but shares no
// modern protocol version with TrustGate. Such a server is not necessarily
// unusable: go-sdk servers answer server/discover even in stateful mode, where
// they deliberately withhold the modern versions while still serving the legacy
// initialize handshake. Only an upstream with no version in common at all is
// reported as incompatible.
func (p *strictProbe) downgrade(remote []string) (probeOutcome, string, error) {
	if latestMutuallySupported(p.legacyVersions, remote) != "" {
		return probeOutcome{kind: probeLegacyCandidate}, "", nil
	}
	outcome, err := incompatibleProbeOutcome()
	return outcome, "", err
}

func supportedVersionsFromError(rpcErr *jsonrpc.Error) []string {
	var data struct {
		Supported []string `json:"supported"`
	}
	if len(rpcErr.Data) == 0 || json.Unmarshal(rpcErr.Data, &data) != nil {
		return nil
	}
	return data.Supported
}

func incompatibleProbeOutcome() (probeOutcome, error) {
	return probeOutcome{kind: probeModernIncompatible}, appmcp.ErrProtocolIncompatible
}

func latestMutuallySupported(local, remote []string) string {
	available := make(map[string]struct{}, len(remote))
	for _, version := range remote {
		available[version] = struct{}{}
	}
	for _, version := range local {
		if _, ok := available[version]; ok {
			return version
		}
	}
	return ""
}

func readBoundedProbeBody(body io.Reader) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(body, maxProbeBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxProbeBodyBytes {
		return nil, errProbeBodyTooLarge
	}
	return raw, nil
}

func probeMessage(contentType string, raw []byte) ([]byte, bool, error) {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return nil, false, errors.New("invalid probe response content type")
	}
	switch strings.ToLower(mediaType) {
	case "application/json":
		return raw, hasTopLevelJSONMember(raw, "result"), nil
	case "text/event-stream":
		return singleSSEData(raw)
	default:
		return nil, false, errors.New("unsupported probe response content type")
	}
}

func singleSSEData(raw []byte) ([]byte, bool, error) {
	normalized := strings.ReplaceAll(string(raw), "\r\n", "\n")
	normalized = strings.ReplaceAll(normalized, "\r", "\n")
	lines := strings.Split(normalized, "\n")
	var events [][]byte
	var data []string
	flush := func() {
		if len(data) == 0 {
			return
		}
		events = append(events, []byte(strings.Join(data, "\n")))
		data = nil
	}
	for _, line := range lines {
		if line == "" {
			flush()
			continue
		}
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		value := strings.TrimPrefix(line, "data:")
		value = strings.TrimPrefix(value, " ")
		data = append(data, value)
	}
	flush()
	hasResultMember := false
	for _, event := range events {
		if hasTopLevelJSONMember(event, "result") {
			hasResultMember = true
		}
	}
	if len(events) != 1 {
		return nil, hasResultMember, errors.New("probe SSE must contain exactly one data event")
	}
	return events[0], hasResultMember, nil
}

func hasTopLevelJSONMember(raw []byte, member string) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return false
	}
	_, ok := fields[member]
	return ok
}

func decodeDiscoverProbeResponse(raw []byte) (*jsonrpc.Response, *discoverProbeResult, error) {
	var envelope struct {
		Result json.RawMessage `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, nil, err
	}
	hasResult := len(envelope.Result) > 0 && string(envelope.Result) != "null"
	hasError := len(envelope.Error) > 0 && string(envelope.Error) != "null"
	if hasResult == hasError {
		return nil, nil, errors.New("probe response must contain exactly one of result or error")
	}

	message, err := jsonrpc.DecodeMessage(raw)
	if err != nil {
		return nil, nil, err
	}
	response, ok := message.(*jsonrpc.Response)
	if !ok {
		return nil, nil, errors.New("probe response is not a JSON-RPC response")
	}
	if response.ID.Raw() != probeRequestID {
		return nil, nil, errors.New("probe response ID does not match request")
	}
	if hasError {
		if response.Error == nil {
			return nil, nil, errors.New("probe response error is invalid")
		}
		return response, nil, nil
	}

	result, err := decodeDiscoverResult(response.Result)
	if err != nil {
		return nil, nil, err
	}
	return response, result, nil
}

func decodeDiscoverResult(raw json.RawMessage) (*discoverProbeResult, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	var result discoverProbeResult
	if err := json.Unmarshal(fields["resultType"], &result.ResultType); err != nil || result.ResultType != "complete" {
		return nil, errors.New("server/discover resultType must be complete")
	}
	if err := json.Unmarshal(fields["supportedVersions"], &result.SupportedVersions); err != nil || len(result.SupportedVersions) == 0 {
		return nil, errors.New("server/discover supportedVersions must be non-empty")
	}
	for _, version := range result.SupportedVersions {
		if version == "" {
			return nil, errors.New("server/discover contains empty protocol version")
		}
	}
	var capabilities map[string]json.RawMessage
	if err := json.Unmarshal(fields["capabilities"], &capabilities); err != nil || capabilities == nil {
		return nil, errors.New("server/discover capabilities must be an object")
	}
	return &result, nil
}

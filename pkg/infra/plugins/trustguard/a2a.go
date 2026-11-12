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
	"context"
	"encoding/json"
	"strings"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
)

// a2aContent returns the text of the text and data parts of a normalised A2A
// body, and its file parts as attachments.
func a2aContent(body []byte) (string, []GuardAttachment, error) {
	var decoded appplugins.A2ABody
	if err := json.Unmarshal(body, &decoded); err != nil {
		return "", nil, err
	}
	var texts []string
	var attachments []GuardAttachment
	for _, part := range decoded.Parts {
		switch part.Type {
		case appplugins.A2APartText:
			texts = append(texts, part.Text)
		case appplugins.A2APartData:
			texts = append(texts, string(part.Data))
		case appplugins.A2APartFile:
			attachments = append(attachments, GuardAttachment{
				Filename:    firstNonEmpty(part.Filename, "file"),
				ContentType: firstNonEmpty(part.MediaType, "application/octet-stream"),
				URL:         part.URL,
				Data:        part.Raw,
			})
		}
	}
	return strings.Join(texts, "\n"), attachments, nil
}

// withinBudget keeps the attachments sent as data while they and the text stay
// within maxBufferedTextBytes, and counts the ones left out.
func withinBudget(attachments []GuardAttachment, textBytes int) ([]GuardAttachment, int) {
	budget := maxBufferedTextBytes - textBytes
	kept := make([]GuardAttachment, 0, len(attachments))
	omitted := 0
	for _, a := range attachments {
		if a.Data != "" {
			if len(a.Data) > budget {
				omitted++
				continue
			}
			budget -= len(a.Data)
		}
		kept = append(kept, a)
	}
	return kept, omitted
}

func a2aPayload(role, text string, attachments []GuardAttachment) (json.RawMessage, error) {
	payload := map[string]any{
		"messages": []map[string]any{{"role": role, "content": text}},
	}
	if len(attachments) > 0 {
		payload["attachments"] = attachments
	}
	return marshalNoEscape(payload)
}

func (p *Plugin) a2aInspectionPayload(
	ctx context.Context,
	in appplugins.ExecInput,
	direction string,
) (json.RawMessage, transformTarget, *inspectionHalt) {
	tgt := transformTarget{isResponse: direction == directionOutput}
	body, role, nothing := in.Request.Body, "user", skipReasonNoInspectableInput
	if tgt.isResponse {
		if reason := outputInspectSkipReason(in.Stage, in.Response, false); reason != "" {
			return p.skipInspection(ctx, in, tgt, direction, reason)
		}
		body, role, nothing = in.Response.Body, "assistant", skipReasonNoInspectableOutput
	}
	text, found, err := a2aContent(body)
	if err != nil {
		return nil, tgt, p.payloadFailure(ctx, in, direction, "trustguard a2a body decode failed", err)
	}
	resolvable, unresolvable := partitionAttachments(found)
	attachments, overBudget := withinBudget(resolvable, len(text))
	tgt.attachmentsOmitted = unresolvable + overBudget
	tgt.textBytes = len(text)
	tgt.urlAttachments = countURLAttachments(attachments)
	tgt.withoutURLAttachments = func() (json.RawMessage, error) {
		return a2aPayload(role, text, dataAttachments(attachments))
	}
	if strings.TrimSpace(text) == "" && len(attachments) == 0 {
		return p.skipInspection(ctx, in, tgt, direction, nothing)
	}
	payload, err := a2aPayload(role, text, attachments)
	if err != nil {
		return nil, tgt, p.payloadFailure(ctx, in, direction, "trustguard a2a payload build failed", err)
	}
	return payload, tgt, nil
}

// a2aMaskRefused answers a mask verdict on A2A, where the gateway cannot
// rewrite parts: it is enforced as a block.
func a2aMaskRefused(in appplugins.ExecInput, data guardData, resp *GuardResponse) (*appplugins.Result, error) {
	data.Decision = guardOutcomeDecision(statusBlock, in.Mode)
	recordGuardOutcome(in.Event, data)
	if data.Decision != decisionBlocked {
		return passThrough(), nil
	}
	refusal := blockError(resp, data.Direction)
	refusal.Type = appplugins.TypeMaskUnsupported
	return nil, refusal
}

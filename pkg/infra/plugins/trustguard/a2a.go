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

// a2aBlock is one text block of an A2A evaluate: the text of a text part,
// read after its Prior, or the JSON of a data part.
type a2aBlock struct {
	part  int
	prior string
	text  string
}

// read is what the block sends: the part's prior context, then its text.
func (b a2aBlock) read() string { return b.prior + b.text }

// a2aContent reads a normalised A2A body: one block per text and data part,
// in order, and its file parts as attachments.
func a2aContent(body []byte) (appplugins.A2ABody, []a2aBlock, []GuardAttachment, error) {
	var decoded appplugins.A2ABody
	if err := json.Unmarshal(body, &decoded); err != nil {
		return decoded, nil, nil, err
	}
	var blocks []a2aBlock
	var attachments []GuardAttachment
	for i, part := range decoded.Parts {
		switch part.Type {
		case appplugins.A2APartText:
			blocks = append(blocks, a2aBlock{part: i, prior: part.Prior, text: part.Text})
		case appplugins.A2APartData:
			blocks = append(blocks, a2aBlock{part: i, text: string(part.Data)})
		case appplugins.A2APartFile:
			attachments = append(attachments, GuardAttachment{
				Filename:    firstNonEmpty(part.Filename, "file"),
				ContentType: firstNonEmpty(part.MediaType, "application/octet-stream"),
				URL:         part.URL,
				Data:        part.Raw,
			})
		}
	}
	return decoded, blocks, attachments, nil
}

// a2aTextBytes is the text the blocks carry.
func a2aTextBytes(blocks []a2aBlock) int {
	n := 0
	for _, b := range blocks {
		n += len(b.read())
	}
	return n
}

// a2aHasText reports whether a block carries text beyond its prior context.
func a2aHasText(blocks []a2aBlock) bool {
	for _, b := range blocks {
		if strings.TrimSpace(b.text) != "" {
			return true
		}
	}
	return false
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

// a2aPayload is the evaluate payload of an A2A body: one message of the
// role, with a text block per text and data part, so TrustGuard reads and
// masks each part on its own and the masks come back part by part.
func a2aPayload(role string, blocks []a2aBlock, attachments []GuardAttachment) (json.RawMessage, error) {
	content := make([]map[string]any, len(blocks))
	for i, b := range blocks {
		content[i] = map[string]any{"type": "text", "text": b.read()}
	}
	payload := map[string]any{
		"messages": []map[string]any{{"role": role, "content": content}},
	}
	if len(attachments) > 0 {
		payload["attachments"] = attachments
	}
	return marshalNoEscape(payload)
}

// a2aMasked writes the masks TrustGuard returns in payload (the blocks of
// a2aPayload, masked) into body's parts, and returns the body to hand back.
// ok is false when they cannot be written: no message or another number of
// blocks, a mask in a part's prior context (text the caller already got), or
// a data part whose masked JSON is no longer JSON.
func a2aMasked(body appplugins.A2ABody, blocks []a2aBlock, payload map[string]any) ([]byte, bool) {
	messages, _ := payload["messages"].([]any)
	if len(messages) != 1 {
		return nil, false
	}
	message, _ := messages[0].(map[string]any)
	content, _ := message["content"].([]any)
	if len(content) != len(blocks) {
		return nil, false
	}
	parts := append([]appplugins.A2APart(nil), body.Parts...)
	for i, b := range blocks {
		item, _ := content[i].(map[string]any)
		masked, ok := item["text"].(string)
		if !ok {
			return nil, false
		}
		if masked == b.read() {
			continue
		}
		text, ok := strings.CutPrefix(masked, b.prior)
		if !ok {
			return nil, false
		}
		switch parts[b.part].Type {
		case appplugins.A2APartText:
			parts[b.part].Text = text
		case appplugins.A2APartData:
			if !json.Valid([]byte(text)) {
				return nil, false
			}
			parts[b.part].Data = json.RawMessage(text)
		}
	}
	body.Parts = parts
	out, err := marshalNoEscape(body)
	if err != nil {
		return nil, false
	}
	return out, true
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
	decoded, blocks, found, err := a2aContent(body)
	if err != nil {
		return nil, tgt, p.payloadFailure(ctx, in, direction, "trustguard a2a body decode failed", err)
	}
	textBytes := a2aTextBytes(blocks)
	resolvable, unresolvable := partitionAttachments(found)
	attachments, overBudget := withinBudget(resolvable, textBytes)
	tgt.attachmentsOmitted = unresolvable + overBudget
	tgt.textBytes = textBytes
	tgt.urlAttachments = countURLAttachments(attachments)
	tgt.withoutURLAttachments = func() (json.RawMessage, error) {
		return a2aPayload(role, blocks, dataAttachments(attachments))
	}
	tgt.applyPayload = func(masked map[string]any) ([]byte, bool) {
		return a2aMasked(decoded, blocks, masked)
	}
	if !a2aHasText(blocks) && len(attachments) == 0 {
		return p.skipInspection(ctx, in, tgt, direction, nothing)
	}
	payload, err := a2aPayload(role, blocks, attachments)
	if err != nil {
		return nil, tgt, p.payloadFailure(ctx, in, direction, "trustguard a2a payload build failed", err)
	}
	return payload, tgt, nil
}

// a2aMaskRefused answers a mask verdict on A2A that cannot be written to the
// parts (see a2aMasked): it is enforced as a block.
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

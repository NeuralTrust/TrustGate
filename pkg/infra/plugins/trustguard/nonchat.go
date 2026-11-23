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
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"strings"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
)

// The routes that are not a chat still carry text a policy is about: the
// prompt of an image, the text a voice reads out, the texts sent to be
// embedded or ranked, and the transcript an audio comes back as. What they
// carry that is not text (an audio upload, an image to edit, a file, token
// ids) cannot be inspected, and is counted as content left out, which a
// policy in failure_mode closed refuses (see uninspectedHalt).
//
// The texts are sent as one message with a text block each, the shape
// TrustGuard masks block by block, and a mask is written back where its text
// came from. A text read from a multipart form has nowhere to be written, so
// a mask of it is refused.

// nonChatText is one text of a non-chat body and where it sits: a path of
// object keys and array indices from the root.
type nonChatText struct {
	path []any
	text string
}

// nonChatBody is what a non-chat body carries: its texts, the decoded JSON
// root they are written back into (nil for a body that is not JSON), and how
// many parts carry content that cannot be inspected.
type nonChatBody struct {
	root   any
	texts  []nonChatText
	opaque int
	// plain is a body that is all text (a transcript asked for as text, srt or
	// vtt): its one text is the whole body.
	plain bool
}

// nonChatRequestPaths are where each route keeps its text. "*" is every item
// of an array; a path that does not reach a string reads nothing.
var nonChatRequestPaths = map[string][][]string{
	providers.CapabilityImages:      {{"prompt"}},
	providers.CapabilityAudioSpeech: {{"input"}, {"instructions"}},
	providers.CapabilityEmbeddings: {
		{"input"}, {"input", "*"}, // OpenAI, Mistral, Voyage…
		{"texts", "*"},                                     // Cohere v1 and v2
		{"inputs", "*", "content", "*", "text"},            // Cohere v2 mixed inputs
		{"inputText"},                                      // Bedrock Titan
		{"content", "parts", "*", "text"},                  // Gemini embedContent
		{"requests", "*", "content", "parts", "*", "text"}, // Gemini batchEmbedContents
		{"instances", "*", "content"},                      // Vertex predict
		{"instances", "*", "title"},
	},
	providers.CapabilityRerank: {{"query"}, {"documents", "*"}, {"documents", "*", "text"}},
}

// nonChatOpaquePaths are where a route keeps content that is not text.
var nonChatOpaquePaths = map[string][][]string{
	providers.CapabilityEmbeddings: {
		{"images", "*"}, {"inputImage"}, {"inputs", "*", "content", "*", "image_url"},
	},
}

// nonChatTranscriptPaths are the texts of a transcription's answer: the
// transcript, and the segments and words verbose_json repeats it in.
var nonChatTranscriptPaths = [][]string{{"text"}, {"segments", "*", "text"}, {"words", "*", "word"}}

// readNonChatRequest reads the texts of a non-chat request body.
func readNonChatRequest(capability, contentType string, body []byte) nonChatBody {
	if len(bytes.TrimSpace(body)) == 0 {
		return nonChatBody{}
	}
	if mediaType, params, err := mime.ParseMediaType(contentType); err == nil && strings.HasPrefix(mediaType, "multipart/") {
		return readMultipart(capability, params["boundary"], body)
	}
	var root any
	if err := decodeJSON(string(body), &root); err != nil {
		// Neither JSON nor a form: nothing here can be read as text.
		return nonChatBody{opaque: 1}
	}
	out := nonChatBody{root: root}
	for _, path := range nonChatRequestPaths[capability] {
		collectAt(root, path, nil, func(at []any, v any) {
			if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
				out.texts = append(out.texts, nonChatText{path: at, text: s})
			}
		})
	}
	for _, path := range nonChatOpaquePaths[capability] {
		collectAt(root, path, nil, func(_ []any, v any) {
			if v != nil {
				out.opaque++
			}
		})
	}
	if capability == providers.CapabilityEmbeddings {
		out.opaque += tokenInputs(root)
	}
	return out
}

// tokenInputs counts the inputs of an embeddings request sent as token ids
// rather than text: an array of numbers, or an array of them.
func tokenInputs(root any) int {
	fields, _ := root.(map[string]any)
	input, ok := fields["input"].([]any)
	if !ok || len(input) == 0 {
		return 0
	}
	switch input[0].(type) {
	case json.Number:
		return 1
	case []any:
		return len(input)
	}
	return 0
}

// readMultipart reads a form: a field is text, a file is content that cannot
// be inspected. The audio of a transcription is not counted: what it says
// comes back as the transcript, which the response leg inspects.
func readMultipart(capability, boundary string, body []byte) nonChatBody {
	out := nonChatBody{}
	if boundary == "" {
		return nonChatBody{opaque: 1}
	}
	reader := multipart.NewReader(bytes.NewReader(body), boundary)
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			return out
		}
		if err != nil {
			out.opaque++
			return out
		}
		if part.FileName() != "" {
			if capability != providers.CapabilityAudioTranscription {
				out.opaque++
			}
			continue
		}
		value, err := io.ReadAll(io.LimitReader(part, maxBufferedTextBytes+1))
		if err != nil {
			out.opaque++
			continue
		}
		if formFieldIsText(part.FormName()) && strings.TrimSpace(string(value)) != "" {
			out.texts = append(out.texts, nonChatText{text: string(value)})
		}
	}
}

// formFieldIsText reports whether a form field carries words rather than an
// option: the prompt of an image edit or of a transcription.
func formFieldIsText(name string) bool {
	switch name {
	case "prompt", "input", "instructions":
		return true
	}
	return false
}

// readNonChatResponse reads the transcript of a transcription's answer: JSON
// with its text, or a body that is all text.
func readNonChatResponse(body []byte) nonChatBody {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nonChatBody{}
	}
	var root any
	if trimmed[0] == '{' && decodeJSON(string(body), &root) == nil {
		out := nonChatBody{root: root}
		for _, path := range nonChatTranscriptPaths {
			collectAt(root, path, nil, func(at []any, v any) {
				if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
					out.texts = append(out.texts, nonChatText{path: at, text: s})
				}
			})
		}
		return out
	}
	return nonChatBody{plain: true, texts: []nonChatText{{text: string(body)}}}
}

// collectAt calls visit with every value at path under v, and where it sits.
func collectAt(v any, path []string, at []any, visit func(at []any, v any)) {
	if len(path) == 0 {
		visit(append([]any(nil), at...), v)
		return
	}
	if path[0] == "*" {
		items, _ := v.([]any)
		for i, item := range items {
			collectAt(item, path[1:], append(at, i), visit)
		}
		return
	}
	fields, ok := v.(map[string]any)
	if !ok {
		return
	}
	if next, ok := fields[path[0]]; ok {
		collectAt(next, path[1:], append(at, path[0]), visit)
	}
}

// setAt writes s at path under root; false when the path no longer leads to
// a string.
func setAt(root any, path []any, s string) bool {
	if len(path) == 0 {
		return false
	}
	parent := root
	for _, step := range path[:len(path)-1] {
		switch key := step.(type) {
		case string:
			fields, ok := parent.(map[string]any)
			if !ok {
				return false
			}
			parent = fields[key]
		case int:
			items, ok := parent.([]any)
			if !ok || key >= len(items) {
				return false
			}
			parent = items[key]
		}
	}
	switch key := path[len(path)-1].(type) {
	case string:
		fields, ok := parent.(map[string]any)
		if !ok {
			return false
		}
		if _, isString := fields[key].(string); !isString {
			return false
		}
		fields[key] = s
	case int:
		items, ok := parent.([]any)
		if !ok || key >= len(items) {
			return false
		}
		if _, isString := items[key].(string); !isString {
			return false
		}
		items[key] = s
	default:
		return false
	}
	return true
}

func (b nonChatBody) textBytes() int {
	n := 0
	for _, t := range b.texts {
		n += len(t.text)
	}
	return n
}

// payload is the evaluate payload: one message of the role, a text block per
// text.
func (b nonChatBody) payload(role string) (json.RawMessage, error) {
	content := make([]map[string]any, len(b.texts))
	for i, t := range b.texts {
		content[i] = map[string]any{"type": "text", "text": t.text}
	}
	return marshalNoEscape(map[string]any{
		"messages": []map[string]any{{"role": role, "content": content}},
	})
}

// masked writes the masks TrustGuard returned (the blocks of payload, masked)
// back into the body. ok is false when they cannot be: another number of
// blocks, or a text with nowhere to be written (a form field).
func (b nonChatBody) masked(original []byte, transformed map[string]any) ([]byte, bool) {
	messages, _ := transformed["messages"].([]any)
	if len(messages) != 1 {
		return nil, false
	}
	message, _ := messages[0].(map[string]any)
	content, _ := message["content"].([]any)
	if len(content) != len(b.texts) {
		return nil, false
	}
	changed := false
	texts := make([]string, len(b.texts))
	for i, t := range b.texts {
		item, _ := content[i].(map[string]any)
		text, ok := item["text"].(string)
		if !ok {
			return nil, false
		}
		texts[i] = text
		changed = changed || text != t.text
	}
	if !changed {
		return original, true
	}
	if b.plain {
		return []byte(texts[0]), true
	}
	if b.root == nil {
		return nil, false
	}
	// The root is decoded once per leg and written once.
	for i, t := range b.texts {
		if texts[i] == t.text {
			continue
		}
		if !setAt(b.root, t.path, texts[i]) {
			return nil, false
		}
	}
	out, err := marshalNoEscape(b.root)
	if err != nil {
		return nil, false
	}
	return out, true
}

// nonChatInspectionPayload is the evaluate payload of a route that is not a
// chat: its request's texts, and the transcript of a transcription's answer.
// Any other answer (vectors, images, audio, a file) has no text and is left
// to the shared response path.
func (p *Plugin) nonChatInspectionPayload(
	ctx context.Context,
	in appplugins.ExecInput,
	direction string,
) (json.RawMessage, transformTarget, *inspectionHalt) {
	tgt := transformTarget{isResponse: direction == directionOutput}
	var read nonChatBody
	var original []byte
	role, nothing := "user", skipReasonNoInspectableInput
	if tgt.isResponse {
		if reason := outputInspectSkipReason(in.Stage, in.Response, false); reason != "" {
			return p.skipInspection(ctx, in, tgt, direction, reason)
		}
		original = in.Response.Body
		read = readNonChatResponse(original)
		role, nothing = "assistant", skipReasonNoInspectableOutput
	} else {
		original = in.Request.Body
		read = readNonChatRequest(in.Request.ProxyCapability, in.Request.HeaderValue("Content-Type"), original)
	}
	tgt.attachmentsOmitted = read.opaque
	tgt.textBytes = read.textBytes()
	if len(read.texts) == 0 {
		return p.skipInspection(ctx, in, tgt, direction, nothing)
	}
	tgt.applyPayload = func(transformed map[string]any) ([]byte, bool) {
		return read.masked(original, transformed)
	}
	payload, err := read.payload(role)
	if err != nil {
		return nil, tgt, p.payloadFailure(ctx, in, direction, "trustguard non-chat payload build failed", err)
	}
	return payload, tgt, nil
}

// isNonChatOutput reports whether an answer on a non-chat route is one this
// plugin reads itself: a transcription's.
func isNonChatOutput(capability string) bool {
	return capability == providers.CapabilityAudioTranscription
}

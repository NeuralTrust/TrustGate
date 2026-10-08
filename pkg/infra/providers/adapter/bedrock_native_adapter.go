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

package adapter

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"sort"
	"strings"
	"unicode/utf8"
)

// FormatBedrockNative tags a native request apart from FormatBedrock, so the read-only
// view never runs on the translated path.
const FormatBedrockNative Format = "bedrock_native"

// BedrockNativeAdapter is the read-only view of native Bedrock traffic, for
// guardrails, DLP, moderation, traces and cost. Its decoders are never used to
// build bytes that are sent: a native request is relayed as received.
//
// Its encoders are the Converse ones, and they exist for exactly one reason: a
// masking plugin changes the text it saw and re-encodes the body through its
// canonical model, and NativeMasker reads that body back, never sends it, to learn
// which text the plugin replaced. The bytes that come out are not the client's
// and are not forwarded; a plugin that changes anything else is refused by the
// executor (appplugins.BedrockNativeAware), not by these encoders.
//
// The view is a union. The model reads whichever fields its family defines,
// and a client can put the text in any of them, or in several at once, so the
// view reads every family whose key is present and then every other text
// bearing string in the body. Picking one shape by the first key would let
// {"inputText":"hello","prompt":"<what the model reads>"} through unseen.
type BedrockNativeAdapter struct {
	converse BedrockAdapter
}

var _ ProviderAdapter = (*BedrockNativeAdapter)(nil)

// nonTextKeys are the keys whose string values are identifiers, enumerations
// and plumbing rather than text a model reads or writes. Anything else that is
// a string is treated as text: the denylist is what keeps the union wide.
var nonTextKeys = map[string]struct{}{
	"anthropic_version": {}, "schemaversion": {}, "model": {}, "modelid": {}, "role": {}, "type": {},
	"stop_reason": {}, "stopreason": {}, "finish_reason": {}, "completionreason": {}, "id": {},
	"format": {}, "media_type": {}, "mediatype": {}, "bytes": {},
	"images": {}, "image": {}, "conditionimage": {}, "maskimage": {}, "inputimage": {}, "base64": {}, "init_image": {},
	"signature": {}, "tooluseid": {}, "ttl": {}, "status": {}, "event_type": {}, "guardrailidentifier": {},
	"guardrailversion": {}, "trace": {}, "version": {}, "encoding": {}, "object": {}, "base64string": {},
}

var toolKeys = map[string]struct{}{
	"toolspec": {}, "tool_use": {}, "tooluse": {}, "tools": {}, "tool_choice": {}, "toolchoice": {},
	"tool_calls": {}, "function": {}, "function_call": {},
}

// textDocumentFormats are the Converse document formats whose bytes are text.
var textDocumentFormats = map[string]struct{}{"txt": {}, "md": {}, "csv": {}, "html": {}}

func isNonTextKey(key string) bool {
	k := strings.ToLower(key)
	if _, ok := nonTextKeys[k]; ok {
		return true
	}
	return strings.HasSuffix(k, "_id")
}

// leftoverText collects every text-bearing string of the body that the family
// decoders did not already surface, so no field the model might read goes
// unseen. known are the texts the decoders already surfaced; a string equal to
// one of them, or to a run of its whole lines, is not repeated. The match is on
// line boundaries on purpose: a substring match made a leftover disappear or
// reappear as the text around it was masked. skipTop names top-level keys that repeat text already
// surfaced.
func leftoverText(raw []byte, known []string, skipTop ...string) string {
	var doc any
	if json.Unmarshal(raw, &doc) != nil {
		return ""
	}
	if m, ok := doc.(map[string]any); ok {
		for _, k := range skipTop {
			delete(m, k)
		}
	}
	var found []string
	collectStrings(doc, false, &found)
	surfaced := newSurfacedIndex(known)
	var extra []string
	seen := map[string]struct{}{}
	for _, s := range found {
		if strings.TrimSpace(s) == "" || surfaced.has(s) {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		extra = append(extra, s)
	}
	return strings.Join(extra, "\n")
}

// The bytes one decode may compare while deduping multi-line leftovers are bounded
// by a multiple of the surfaced text, plus a floor; past it a string is kept without
// the check, which only repeats text. Charging bytes and not comparisons is what
// keeps near-equal long lines from multiplying the work.
const (
	surfacedBudgetFactor = 16
	surfacedBudgetFloor  = 1 << 20
)

type linePos struct{ text, line int }

// surfacedIndex answers, without rescanning the surfaced texts for each string,
// whether a string is a whole line, or a run of whole lines, of one of them.
// Matching on line boundaries keeps "Paris" a leftover next to a message about
// "Paris Hilton", before and after that message is masked.
type surfacedIndex struct {
	texts  [][]string
	lines  map[string]struct{}
	first  map[string][]linePos
	budget int
}

func newSurfacedIndex(known []string) *surfacedIndex {
	idx := &surfacedIndex{
		lines: map[string]struct{}{},
		first: map[string][]linePos{},
	}
	total := 0
	for _, k := range known {
		total += len(k)
		if k == "" {
			continue
		}
		lines := strings.Split(k, "\n")
		t := len(idx.texts)
		idx.texts = append(idx.texts, lines)
		for i, l := range lines {
			idx.lines[l] = struct{}{}
			idx.first[l] = append(idx.first[l], linePos{t, i})
		}
	}
	idx.budget = surfacedBudgetFloor + surfacedBudgetFactor*total
	return idx
}

func (x *surfacedIndex) has(s string) bool {
	if !strings.Contains(s, "\n") {
		_, ok := x.lines[s]
		return ok
	}
	run := strings.Split(s, "\n")
	for _, at := range x.first[run[0]] {
		if x.budget <= 0 {
			return false
		}
		text := x.texts[at.text]
		x.budget--
		if at.line+len(run) > len(text) {
			continue
		}
		matched := true
		for i := 1; i < len(run); i++ {
			x.budget -= len(run[i]) + 1
			if text[at.line+i] != run[i] {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

// binaryBlobMinLen is the length from which a base64 string is told from a token.
const binaryBlobMinLen = 1024

// isBinaryBlob reports a long base64 string, standard or URL alphabet, padded or
// not, whose bytes start with the signature of a known media file: an image, audio,
// video, PDF or archive a model does not read as words. Anything else stays in the
// view, because it is text the model may read: prose without spaces, text in
// another encoding, base64 that merely does not decode to UTF-8.
func isBinaryBlob(s string) bool {
	if len(s) < binaryBlobMinLen {
		return false
	}
	head := s[:mediaProbeChars]
	for i := 0; i < len(head); i++ {
		c := head[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '+', c == '/', c == '-', c == '_':
		default:
			return false
		}
	}
	for i := mediaProbeChars; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '+', c == '/', c == '-', c == '_', c == '=':
		default:
			return false
		}
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.NewReplacer("+", "-", "/", "_").Replace(head))
	if err != nil {
		return false
	}
	return hasMediaSignature(raw)
}

const mediaProbeChars = 32

func hasMediaSignature(b []byte) bool {
	for _, sig := range mediaPrefixes {
		if bytes.HasPrefix(b, sig) {
			return true
		}
	}
	if len(b) >= 12 {
		switch {
		case string(b[4:8]) == "ftyp":
			return true
		case string(b[:4]) == "RIFF" && (string(b[8:12]) == "WEBP" || string(b[8:12]) == "WAVE" || string(b[8:12]) == "AVI "):
			return true
		}
	}
	return false
}

var mediaPrefixes = [][]byte{
	{0x89, 'P', 'N', 'G'}, {0xFF, 0xD8, 0xFF}, []byte("GIF8"), []byte("%PDF"), []byte("ID3"),
	{0xFF, 0xFB}, {0xFF, 0xFA}, {0xFF, 0xF3}, {0xFF, 0xF2}, {0xFF, 0xE3}, []byte("OggS"), []byte("fLaC"),
	{0xFF, 0xF1}, {0xFF, 0xF9}, // AAC ADTS
	{0x1A, 0x45, 0xDF, 0xA3}, // EBML: WebM, MKV
	[]byte("FLV"),
	{0x30, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11}, // ASF: WMV, WMA
	{0x00, 0x00, 0x01, 0xBA},                         // MPEG program stream
	{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, // OLE: legacy Office
	{'P', 'K', 0x03, 0x04}, {'I', 'I', '*', 0x00}, {'M', 'M', 0x00, '*'}, []byte("BM"),
}

func stringOf(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

func decodedText(b64 string) string {
	text, _, _ := decodeDocument(b64)
	return text
}

// decodeDocument decodes the base64 of a text document, padded or not: SDKs and
// clients write both. raw reports the unpadded form, so a mask can write the
// document back the way it was sent. ok is false when the string is not base64 or
// does not decode to valid UTF-8.
func decodeDocument(b64 string) (text string, raw, ok bool) {
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(b64)
		raw = true
	}
	if err != nil || !utf8.Valid(decoded) {
		return "", false, false
	}
	return string(decoded), raw, true
}

func encodeDocument(text string, raw bool) string {
	if raw {
		return base64.RawStdEncoding.EncodeToString([]byte(text))
	}
	return base64.StdEncoding.EncodeToString([]byte(text))
}

// HasS3Source reports an S3 location a model service would fetch with the
// registry's credentials: any object member named s3Location (any casing) whose
// value is an object carrying a uri. That covers the Converse image, document and
// video sources and the TwelveLabs mediaSource, wherever they sit. Bedrock reads it
// out of band, so it is in no body a policy can read; the caller refuses the
// request. Tool data (tool call arguments, tool results, tool schemas) is arbitrary
// client data and is not searched.
func HasS3Source(body []byte) bool {
	root, ok := parseJSON(body)
	if !ok {
		return false
	}
	var walk func(n *jnode) bool
	walk = func(n *jnode) bool {
		switch n.kind {
		case 'a':
			for _, v := range n.vals {
				if walk(v) {
					return true
				}
			}
		case 'o':
			toolUse := n.strMember("type") == "tool_use" || n.member("toolUseId") != nil
			for i, k := range n.keys {
				lk := strings.ToLower(k)
				v := n.vals[i]
				if isToolDataKey(lk, toolUse) {
					continue
				}
				if lk == "s3location" && v.kind == 'o' && hasKeyFold(v, "uri") {
					return true
				}
				if walk(v) {
					return true
				}
			}
		}
		return false
	}
	return walk(root)
}

// isToolDataKey names the members that hold client-defined tool data: call
// arguments, JSON tool results and tool schemas.
func isToolDataKey(lk string, inToolUse bool) bool {
	switch lk {
	case "json", "toolspec", "toolconfig", "input_schema", "inputschema":
		return true
	case "input":
		return inToolUse
	}
	return false
}

func hasKeyFold(n *jnode, key string) bool {
	for _, k := range n.keys {
		if strings.EqualFold(k, key) {
			return true
		}
	}
	return false
}

// HasUninspectableDocument reports a text document in a request that the view
// cannot read: its bytes are not base64, or not valid UTF-8. The model reads
// whatever the client sent, so leaving such a document out of the view would be
// leaving text out of what policies see; the caller refuses the request.
func HasUninspectableDocument(body []byte) bool {
	root, ok := parseJSON(body)
	if !ok {
		return false
	}
	var walk func(n *jnode) bool
	walk = func(n *jnode) bool {
		switch n.kind {
		case 'a':
			for _, v := range n.vals {
				if walk(v) {
					return true
				}
			}
		case 'o':
			if src := documentSourceString(n); src != nil {
				if _, _, ok := decodeDocument(src.str); !ok {
					return true
				}
			}
			for _, v := range n.vals {
				if walk(v) {
					return true
				}
			}
		}
		return false
	}
	return walk(root)
}

func documentText(m map[string]any) string {
	if src, ok := m["source"].(map[string]any); ok {
		if _, text := textDocumentFormats[strings.ToLower(stringOf(m, "format"))]; text {
			if b, ok := src["bytes"].(string); ok {
				return decodedText(b)
			}
		}
		if stringOf(src, "type") == "base64" && strings.HasPrefix(strings.ToLower(stringOf(src, "media_type")), "text/") {
			if d, ok := src["data"].(string); ok {
				return decodedText(d)
			}
		}
	}
	return ""
}

func collectStrings(v any, inTool bool, out *[]string) {
	switch t := v.(type) {
	case string:
		if !isBinaryBlob(t) {
			*out = append(*out, t)
		}
	case []any:
		for _, item := range t {
			collectStrings(item, inTool, out)
		}
	case map[string]any:
		if text := documentText(t); text != "" {
			*out = append(*out, text)
		}
		inTool = inTool || stringOf(t, "type") == "tool_use"
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			lk := strings.ToLower(k)
			switch {
			case lk == "name" && inTool:
				continue
			case lk == "data" && stringOf(t, "type") == "base64":
				continue
			case lk == "properties":
				if props, ok := t[k].(map[string]any); ok {
					names := make([]string, 0, len(props))
					for pk := range props {
						names = append(names, pk)
					}
					sort.Strings(names)
					*out = append(*out, names...)
				}
			case isNonTextKey(k):
				continue
			}
			_, tool := toolKeys[lk]
			collectStrings(t[k], inTool || tool, out)
		}
	}
}

// HasInvalidText reports a body that is not valid UTF-8 or that carries an
// unpaired surrogate escape. encoding/json turns both into U+FFFD, so the view
// would read different text than a model tokenizer given the raw bytes.
func HasInvalidText(b []byte) bool {
	if !utf8.Valid(b) {
		return true
	}
	for i := 0; i < len(b); i++ {
		if b[i] != '\\' {
			continue
		}
		if i+1 >= len(b) {
			return true
		}
		if b[i+1] != 'u' {
			i++
			continue
		}
		code, ok := hex4(b, i+2)
		if !ok {
			return true
		}
		i += 5
		switch {
		case code >= 0xD800 && code <= 0xDBFF:
			low, ok := uint16(0), false
			if i+6 < len(b) && b[i+1] == '\\' && b[i+2] == 'u' {
				low, ok = hex4(b, i+3)
			}
			if !ok || low < 0xDC00 || low > 0xDFFF {
				return true
			}
			i += 6
		case code >= 0xDC00 && code <= 0xDFFF:
			return true
		}
	}
	return false
}

func hex4(b []byte, at int) (uint16, bool) {
	if at+4 > len(b) {
		return 0, false
	}
	var v uint16
	for _, c := range b[at : at+4] {
		switch {
		case c >= '0' && c <= '9':
			v = v<<4 | uint16(c-'0')
		case c >= 'a' && c <= 'f':
			v = v<<4 | uint16(c-'a'+10)
		case c >= 'A' && c <= 'F':
			v = v<<4 | uint16(c-'A'+10)
		default:
			return 0, false
		}
	}
	return v, true
}

func (a *BedrockNativeAdapter) DecodeRequest(body []byte) (*CanonicalRequest, error) {
	cr, err := a.modelledRequest(body)
	if err != nil {
		return nil, err
	}
	if extra := leftoverText(body, requestParts(cr)); extra != "" {
		cr.Messages = append(cr.Messages, CanonicalMessage{Role: roleUser, Content: extra})
	}
	return cr, nil
}

// modelledRequest is the request as the family decoders read it, without the
// strings no decoder models; DecodeRequest adds those on top.
func (a *BedrockNativeAdapter) modelledRequest(body []byte) (*CanonicalRequest, error) {
	fields, ok := jsonFields(body)
	if !ok {
		return a.converse.DecodeRequest(body)
	}
	var parts []*CanonicalRequest
	add := func(cr *CanonicalRequest, err error) {
		if err == nil && cr != nil {
			parts = append(parts, cr)
		}
	}
	if hasField(fields, "anthropic_version") {
		add((&AnthropicAdapter{}).DecodeRequest(body))
	}
	if hasField(fields, "inputText") {
		add(decodeTitanRequest(body), nil)
	}
	if isStringField(fields, "prompt") {
		add(decodePromptRequest(body), nil)
	}
	if isStringField(fields, "message") {
		add(decodeCohereChatRequest(body), nil)
	}
	switch {
	case hasField(fields, "anthropic_version"):
	case hasField(fields, "messages") && messagesAreOpenAI(fields["messages"]):
		add((&OpenAIAdapter{}).DecodeRequest(body))
	case hasField(fields, "messages"):
		add(a.converse.DecodeRequest(body))
	case hasField(fields, converseRequestKeys...):
		add(a.converse.DecodeRequest(body))
	}
	return mergeRequests(parts), nil
}

func mergeRequests(parts []*CanonicalRequest) *CanonicalRequest {
	out := &CanonicalRequest{}
	var systems []string
	for _, p := range parts {
		if p.System != "" {
			systems = append(systems, p.System)
		}
		out.Messages = append(out.Messages, p.Messages...)
		out.Tools = append(out.Tools, p.Tools...)
		if out.MaxTokens == 0 {
			out.MaxTokens = p.MaxTokens
		}
		if out.Temperature == nil {
			out.Temperature = p.Temperature
		}
		if out.TopP == nil {
			out.TopP = p.TopP
		}
		if len(out.Stop) == 0 {
			out.Stop = p.Stop
		}
		if out.ToolChoice == nil {
			out.ToolChoice = p.ToolChoice
		}
		out.Stream = out.Stream || p.Stream
		if out.Model == "" {
			out.Model = p.Model
		}
	}
	out.System = strings.Join(systems, "\n\n")
	return out
}

func requestParts(cr *CanonicalRequest) []string {
	parts := []string{cr.System}
	for _, m := range cr.Messages {
		parts = append(parts, m.Content)
		for _, tc := range m.ToolCalls {
			parts = append(parts, tc.Arguments)
		}
	}
	return parts
}

func responseParts(cr *CanonicalResponse) []string {
	parts := []string{cr.Content}
	for _, tc := range cr.ToolCalls {
		parts = append(parts, tc.Arguments)
	}
	return parts
}

func requestText(cr *CanonicalRequest) string {
	var sb strings.Builder
	sb.WriteString(cr.System)
	for _, m := range cr.Messages {
		sb.WriteByte('\n')
		sb.WriteString(m.Content)
		for _, tc := range m.ToolCalls {
			sb.WriteByte('\n')
			sb.WriteString(tc.Arguments)
		}
	}
	return sb.String()
}

func (a *BedrockNativeAdapter) EncodeRequest(req *CanonicalRequest) ([]byte, error) {
	return a.converse.EncodeRequest(req)
}

func (a *BedrockNativeAdapter) DecodeResponse(body []byte) (*CanonicalResponse, error) {
	out, err := a.modelledResponse(body)
	if err != nil {
		return nil, err
	}
	if extra := leftoverText(body, responseParts(out)); extra != "" {
		if out.Content != "" {
			out.Content += "\n"
		}
		out.Content += extra
	}
	return out, nil
}

func (a *BedrockNativeAdapter) modelledResponse(body []byte) (*CanonicalResponse, error) {
	fields, ok := jsonFields(body)
	if !ok {
		return a.converse.DecodeResponse(body)
	}
	var parts []*CanonicalResponse
	add := func(cr *CanonicalResponse, err error) {
		if err == nil && cr != nil {
			parts = append(parts, cr)
		}
	}
	if hasField(fields, "output") {
		add(a.converse.DecodeResponse(body))
	}
	if stringField(fields, "type") == "message" {
		add((&AnthropicAdapter{}).DecodeResponse(body))
	}
	if hasField(fields, "choices") {
		add((&OpenAIAdapter{}).DecodeResponse(body))
	}
	if hasField(fields, "results") {
		add(decodeTitanResponse(body), nil)
	}
	if hasField(fields, "generation") {
		add(decodeLlamaResponse(body), nil)
	}
	if hasField(fields, "outputs") {
		add(decodeMistralResponse(body), nil)
	}
	if hasField(fields, "generations") || isStringField(fields, "text") {
		add(decodeCohereResponse(body), nil)
	}
	out := &CanonicalResponse{Role: roleAssistant}
	for _, p := range parts {
		if p.Role != "" && out.Role == roleAssistant {
			out.Role = p.Role
		}
		out.Content += p.Content
		out.ToolCalls = append(out.ToolCalls, p.ToolCalls...)
		if out.FinishReason == "" {
			out.FinishReason = p.FinishReason
		}
		out.Usage = MergeUsage(out.Usage, p.Usage)
		if out.Reasoning == nil {
			out.Reasoning = p.Reasoning
		}
		if out.ID == "" {
			out.ID = p.ID
		}
		if out.Model == "" {
			out.Model = p.Model
		}
	}
	return out, nil
}

func (a *BedrockNativeAdapter) EncodeResponse(resp *CanonicalResponse) ([]byte, error) {
	return a.converse.EncodeResponse(resp)
}

func (a *BedrockNativeAdapter) DecodeStreamChunk(chunk []byte) (*CanonicalStreamChunk, error) {
	fields, ok := jsonFields(chunk)
	if !ok {
		return nil, nil
	}
	if hasField(fields, converseStreamKeys...) {
		return a.converse.DecodeStreamChunk(chunk)
	}
	var out *CanonicalStreamChunk
	merge := func(c *CanonicalStreamChunk, err error) {
		if err != nil || c == nil {
			return
		}
		if out == nil {
			out = &CanonicalStreamChunk{}
		}
		out.Delta += c.Delta
		out.ReasoningDelta += c.ReasoningDelta
		out.ToolCallDeltas = append(out.ToolCallDeltas, c.ToolCallDeltas...)
		if out.FinishReason == "" {
			out.FinishReason = c.FinishReason
		}
		if out.Role == "" {
			out.Role = c.Role
		}
		if out.ID == "" {
			out.ID = c.ID
		}
		if out.Model == "" {
			out.Model = c.Model
		}
		out.Usage = MergeUsage(out.Usage, c.Usage)
	}
	if isStringField(fields, "type") {
		merge((&AnthropicAdapter{}).DecodeStreamChunk(chunk))
	}
	if hasField(fields, "choices") {
		merge((&OpenAIAdapter{}).DecodeStreamChunk(chunk))
	}
	if hasField(fields, "outputText") {
		merge(decodeTitanChunk(chunk), nil)
	}
	if hasField(fields, "generation") {
		merge(decodeLlamaChunk(chunk), nil)
	}
	if hasField(fields, "outputs") {
		merge(decodeMistralChunk(chunk), nil)
	}
	if hasField(fields, "event_type", "is_finished") || isStringField(fields, "text") {
		merge(decodeCohereChunk(chunk), nil)
	}
	if usage := invocationMetricsUsage(fields[invocationMetricsKey]); usage != nil {
		merge(&CanonicalStreamChunk{Usage: usage}, nil)
	}
	var known []string
	if out != nil {
		known = append(known, out.Delta, out.ReasoningDelta)
		for _, tc := range out.ToolCallDeltas {
			known = append(known, tc.Name, tc.ArgumentsDelta)
		}
	}
	// Cohere repeats the whole answer in "response" on its closing event.
	var skip []string
	if stringField(fields, "event_type") == "stream-end" {
		skip = append(skip, "response")
	}
	if extra := leftoverText(chunk, known, skip...); extra != "" {
		if out == nil {
			out = &CanonicalStreamChunk{}
		}
		if out.Delta != "" {
			out.Delta += "\n"
		}
		out.Delta += extra
	}
	return out, nil
}

func (a *BedrockNativeAdapter) EncodeStreamChunk(chunk *CanonicalStreamChunk) ([][]byte, error) {
	return a.converse.EncodeStreamChunk(chunk)
}

// nativeKeyShape is the precise key shape of the family a native body is in,
// for the repeated-key and case-fold check. Only a body of no known family is
// checked with every object as a struct: applying that to a family that holds
// client-owned objects, such as a tool's JSON schema, would refuse valid
// requests.
func nativeKeyShape(b []byte) *keyShape {
	fields, ok := jsonFields(b)
	if !ok {
		return strictShape
	}
	switch sniffInvokeRequest(fields) {
	case shapeAnthropic:
		return anthropicShape
	case shapeOpenAI:
		return chatShape
	case shapeConverse:
		return bedrockShape
	default:
		return strictShape
	}
}

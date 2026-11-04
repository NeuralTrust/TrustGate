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

package events

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	multipartPlaceholder = `{"_multipart": true}`
	truncatedSuffix      = "...[truncated]"

	// MaxSanitizedBodyBytes caps the request/response bodies kept for Activity
	// traces. Truncation must happen here so it is always explicit and marked
	// (_nt_truncated for JSON, the ...[truncated] suffix otherwise); the OTel
	// attribute limit is deliberately kept above this value so the SDK never
	// silently cuts a body mid-JSON.
	MaxSanitizedBodyBytes = 1 << 20

	redactedValue = "[REDACTED]"

	// maxJSONStringNesting bounds how many levels of JSON carried in a string
	// value the redaction parses. A prompt or tool-call arguments are one.
	maxJSONStringNesting = 4

	// maxEmbeddedJSONScanBytes bounds how many bytes RedactCredentialsInText
	// reads while it tries brackets as JSON in one text.
	maxEmbeddedJSONScanBytes = MaxSanitizedBodyBytes

	bearerRedacted = "Bearer " + redactedValue
	basicRedacted  = "Basic " + redactedValue
)

var credentialBodyKeys = map[string]struct{}{
	"password":         {},
	"passwd":           {},
	"secret":           {},
	"token":            {},
	"api_key":          {},
	"apikey":           {},
	"authorization":    {},
	"credential":       {},
	"access_token":     {},
	"refresh_token":    {},
	"id_token":         {},
	"code_verifier":    {},
	"subject_token":    {},
	"actor_token":      {},
	"client_assertion": {},
	"client_secret":    {},
	"private_key":      {},
}

var sensitiveHeaders = map[string]struct{}{
	"authorization":          {},
	"proxy-authorization":    {},
	"www-authenticate":       {},
	"authentication":         {},
	"cookie":                 {},
	"set-cookie":             {},
	"x-api-key":              {},
	"api-key":                {},
	"x-tg-api-key":           {},
	"x-ag-api-key":           {},
	"x-ag-playground-token":  {},
	"x-ag-diagnostics-token": {},
	"x-auth-token":           {},
	"x-access-token":         {},
	"x-amz-security-token":   {},
	"x-amz-credential":       {},
	"x-goog-api-key":         {},
	"x-csrf-token":           {},
	"x-xsrf-token":           {},
}

// SanitizeBody returns a loggable representation of a request/response body,
// capped at MaxSanitizedBodyBytes.
func SanitizeBody(body []byte, headers map[string][]string) string {
	return sanitizeBody(body, headers, MaxSanitizedBodyBytes)
}

// SanitizeExtras redacts credential-shaped keys from plugin extras before export.
func SanitizeExtras(extras any) any {
	if extras == nil {
		return nil
	}
	raw, err := json.Marshal(extras)
	if err != nil {
		return nil
	}
	var generic any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return nil
	}
	stripped, _ := stripCredentialBodyValue(generic, 0)
	return stripped
}

// RedactCredentialsInText redacts the values under credential keys in every
// JSON object or array text holds, whole or pasted among prose, as a prompt
// whose parts were joined does. It reads text only until keep runes other than
// whitespace are out and returns that prefix: a caller that cuts the text
// there never shows the rest. The brackets tried as JSON read at most
// maxEmbeddedJSONScanBytes between them, so prose full of brackets stays
// linear in that budget.
func RedactCredentialsInText(text string, keep int) string {
	if redacted, changed := stripCredentialJSONString(text, 0); changed {
		out, _ := redacted.(string)
		return out
	}
	var b strings.Builder
	kept, budget := 0, maxEmbeddedJSONScanBytes
	for i := 0; i < len(text) && kept <= keep; {
		if c := text[i]; (c == '{' || c == '[') && budget > 0 {
			value, n, read, ok := redactEmbeddedJSON(text[i:], budget)
			budget -= read
			if ok {
				b.WriteString(value)
				kept += countNonSpaceRunes(value)
				i += n
				continue
			}
		}
		r, size := utf8.DecodeRuneInString(text[i:])
		b.WriteString(text[i : i+size])
		if !unicode.IsSpace(r) {
			kept++
		}
		i += size
	}
	return b.String()
}

// redactEmbeddedJSON decodes the JSON value text starts with, reading at most
// budget bytes, and returns it with its credentials redacted, how many bytes
// of text it took and how many the decoder read.
func redactEmbeddedJSON(text string, budget int) (value string, n, read int, ok bool) {
	src := &countingReader{r: strings.NewReader(text[:min(len(text), budget)])}
	dec := json.NewDecoder(src)
	var decoded any
	if err := dec.Decode(&decoded); err != nil {
		return "", 0, src.n, false
	}
	n = int(dec.InputOffset())
	stripped, changed := stripCredentialBodyValue(decoded, 1)
	if !changed {
		return text[:n], n, src.n, true
	}
	out, err := json.Marshal(stripped)
	if err != nil {
		return redactedValue, n, src.n, true
	}
	return string(out), n, src.n, true
}

type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

func countNonSpaceRunes(s string) int {
	n := 0
	for _, r := range s {
		if !unicode.IsSpace(r) {
			n++
		}
	}
	return n
}

func sanitizeBody(body []byte, headers map[string][]string, maxBytes int) string {
	if len(body) == 0 {
		return ""
	}

	contentType := lookupHeader(headers, "Content-Type")
	if contentType == "" {
		if stripped, ok := tryStripJSONCredentials(body); ok {
			return capBody(stripped, maxBytes)
		}
		return capBody(body, maxBytes)
	}

	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		if stripped, ok := tryStripJSONCredentials(body); ok {
			return capBody(stripped, maxBytes)
		}
		return capBody(body, maxBytes)
	}

	if mediaType == "multipart/form-data" {
		return extractMultipartFileNames(body, params["boundary"])
	}

	if isJSONMediaType(mediaType) {
		return capBody(stripCredentialJSONBody(body), maxBytes)
	}

	return capBody(body, maxBytes)
}

func isJSONMediaType(mediaType string) bool {
	return mediaType == "application/json" || strings.HasSuffix(mediaType, "+json")
}

func tryStripJSONCredentials(body []byte) ([]byte, bool) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, false
	}
	switch trimmed[0] {
	case '{', '[':
	default:
		return nil, false
	}
	return stripCredentialJSONBody(trimmed), true
}

func stripCredentialJSONBody(body []byte) []byte {
	if len(body) == 0 {
		return body
	}
	var generic any
	if err := json.Unmarshal(body, &generic); err != nil {
		return body
	}
	stripped, changed := stripCredentialBodyValue(generic, 0)
	if !changed {
		return body
	}
	out, err := json.Marshal(stripped)
	if err != nil {
		return body
	}
	return out
}

// stripCredentialBodyValue redacts the values under credential keys and
// reports whether it found any, so a body without credentials is kept byte for
// byte instead of re-encoded. nesting counts the JSON-in-string levels above v.
func stripCredentialBodyValue(v any, nesting int) (any, bool) {
	switch t := v.(type) {
	case map[string]any:
		changed := false
		for key, val := range t {
			if isCredentialBodyKey(key) {
				t[key] = stripCredentialBodyLeaf(val, nesting)
				changed = true
				continue
			}
			var c bool
			t[key], c = stripCredentialBodyValue(val, nesting)
			changed = changed || c
		}
		return t, changed
	case []any:
		changed := false
		for i := range t {
			var c bool
			t[i], c = stripCredentialBodyValue(t[i], nesting)
			changed = changed || c
		}
		return t, changed
	case string:
		return stripCredentialJSONString(t, nesting)
	default:
		return v, false
	}
}

// stripCredentialJSONString redacts credential keys inside a string value that
// itself holds a JSON object or array, such as a prompt or tool-call
// arguments. A string that is not JSON, or holds no credential key, is
// returned as is. Each level re-parses its string, and \u escapes let a level
// cost only a few more bytes than the one inside it, so a body can stack
// hundreds of levels per MiB. Past maxJSONStringNesting a string that looks
// like JSON is redacted whole without parsing it, so the work stays linear in
// the body size.
func stripCredentialJSONString(s string, nesting int) (any, bool) {
	trimmed := strings.TrimSpace(s)
	if len(trimmed) < 2 || (trimmed[0] != '{' && trimmed[0] != '[' && trimmed[0] != '"') {
		return s, false
	}
	if nesting >= maxJSONStringNesting {
		return redactedValue, true
	}
	if trimmed[0] == '"' {
		// JSON encoded twice, as a tool result marshalled once too often is.
		var decoded string
		if err := json.Unmarshal([]byte(trimmed), &decoded); err != nil {
			return s, false
		}
		stripped, changed := stripCredentialJSONString(decoded, nesting+1)
		if !changed {
			return s, false
		}
		out, err := json.Marshal(stripped)
		if err != nil {
			return redactedValue, true
		}
		return string(out), true
	}
	var inner any
	if err := json.Unmarshal([]byte(trimmed), &inner); err != nil {
		return s, false
	}
	stripped, changed := stripCredentialBodyValue(inner, nesting+1)
	if !changed {
		return s, false
	}
	out, err := json.Marshal(stripped)
	if err != nil {
		return redactedValue, true
	}
	return string(out), true
}

func stripCredentialBodyLeaf(v any, nesting int) any {
	switch t := v.(type) {
	case string:
		return redactedValue
	case []any:
		for i := range t {
			t[i] = stripCredentialBodyLeaf(t[i], nesting)
		}
		return t
	case map[string]any:
		stripped, _ := stripCredentialBodyValue(t, nesting)
		return stripped
	default:
		return v
	}
}

// IsCredentialKey reports whether a JSON body key names a credential that
// SanitizeBody redacts.
func IsCredentialKey(key string) bool {
	return isCredentialBodyKey(key)
}

func isCredentialBodyKey(key string) bool {
	lower := strings.ToLower(strings.TrimSpace(key))
	if _, ok := credentialBodyKeys[lower]; ok {
		return true
	}
	switch {
	case lower == "apikey":
		return true
	case strings.HasSuffix(lower, "_api_key"):
		return true
	case strings.HasSuffix(lower, "-api-key"):
		return true
	case strings.HasSuffix(lower, "_apikey"):
		return true
	}
	return false
}

func isSensitiveHeader(key string) bool {
	lower := strings.ToLower(key)
	if _, ok := sensitiveHeaders[lower]; ok {
		return true
	}
	return strings.HasSuffix(lower, "-api-key") || lower == "apikey"
}

// RedactHeaders returns a copy of headers with sensitive values replaced.
func RedactHeaders(headers map[string][]string) map[string][]string {
	if headers == nil {
		return nil
	}
	out := make(map[string][]string, len(headers))
	for key, values := range headers {
		if isSensitiveHeader(key) {
			redacted := make([]string, len(values))
			for i, v := range values {
				redacted[i] = redactCredentialHeaderValue(key, v)
			}
			out[key] = redacted
			continue
		}
		out[key] = values
	}
	return out
}

func redactCredentialHeaderValue(headerKey, value string) string {
	switch strings.ToLower(headerKey) {
	case "authorization", "proxy-authorization":
		trimmed := strings.TrimSpace(value)
		lower := strings.ToLower(trimmed)
		if strings.HasPrefix(lower, "bearer ") {
			return bearerRedacted
		}
		if strings.HasPrefix(lower, "basic ") {
			return basicRedacted
		}
	}
	return redactedValue
}

func capBody(body []byte, maxBytes int) string {
	if maxBytes <= 0 || len(body) <= maxBytes {
		return string(body)
	}
	if capped, ok := capJSONBody(body, maxBytes); ok {
		return capped
	}
	return string(body[:maxBytes]) + truncatedSuffix
}

// capJSONBody shrinks a JSON payload to fit maxBytes while keeping valid JSON.
// Chat-style bodies keep messages[] parseable so Activity can still render them.
func capJSONBody(body []byte, maxBytes int) (string, bool) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return "", false
	}
	switch trimmed[0] {
	case '{', '[':
	default:
		return "", false
	}

	var generic any
	if err := json.Unmarshal(trimmed, &generic); err != nil {
		return "", false
	}

	switch root := generic.(type) {
	case map[string]any:
		root["_nt_truncated"] = true
		if !shrinkJSONMap(root, maxBytes) {
			return "", false
		}
		out, err := json.Marshal(root)
		if err != nil || len(out) > maxBytes {
			return "", false
		}
		return string(out), true
	case []any:
		shrunk := shrinkJSONArray(root, maxBytes)
		out, err := json.Marshal(shrunk)
		if err != nil || len(out) > maxBytes {
			return "", false
		}
		return string(out), true
	default:
		return "", false
	}
}

func shrinkJSONMap(m map[string]any, maxBytes int) bool {
	if fitsJSON(m, maxBytes) {
		return true
	}
	if msgs, ok := m["messages"].([]any); ok && len(msgs) > 0 {
		m["messages"] = shrinkMessages(msgs, maxBytes, m)
		if fitsJSON(m, maxBytes) {
			return true
		}
	}
	if contents, ok := m["contents"].([]any); ok && len(contents) > 0 {
		m["contents"] = shrinkGeminiContents(contents, maxBytes, m)
		if fitsJSON(m, maxBytes) {
			return true
		}
	}
	// Drop bulky non-essential keys after messages are already minimized.
	for _, key := range []string{"tools", "functions", "tool_choice", "function_call", "toolsConfig", "generationConfig", "safetySettings"} {
		if _, ok := m[key]; ok {
			delete(m, key)
			m["_nt_truncated"] = true
			if fitsJSON(m, maxBytes) {
				return true
			}
		}
	}
	truncateStringLeaves(m, maxBytes)
	return fitsJSON(m, maxBytes)
}

func shrinkJSONArray(arr []any, maxBytes int) []any {
	out := arr
	for len(out) > 1 && !fitsJSON(out, maxBytes) {
		out = out[:len(out)-1]
	}
	if !fitsJSON(out, maxBytes) {
		truncateStringLeaves(out, maxBytes)
	}
	return out
}

// shrinkMessages keeps the first message (often system) and the newest tail,
// dropping middle history until the whole object fits maxBytes.
func shrinkMessages(msgs []any, maxBytes int, parent map[string]any) []any {
	if len(msgs) == 0 {
		return msgs
	}
	out := append([]any(nil), msgs...)
	for len(out) > 2 && !fitsJSONWithMessages(parent, out, maxBytes) {
		// Drop the oldest non-head message (index 1) so system + recent turns remain.
		out = append(out[:1], out[2:]...)
	}
	for len(out) > 1 && !fitsJSONWithMessages(parent, out, maxBytes) {
		out = out[1:]
	}
	if !fitsJSONWithMessages(parent, out, maxBytes) {
		truncateStringLeaves(out, maxBytes)
	}
	return out
}

func fitsJSONWithMessages(parent map[string]any, msgs []any, maxBytes int) bool {
	parent["messages"] = msgs
	return fitsJSON(parent, maxBytes)
}

// shrinkGeminiContents keeps the first content turn and the newest tail, like
// shrinkMessages, so Activity can still parse Gemini generateContent bodies.
func shrinkGeminiContents(contents []any, maxBytes int, parent map[string]any) []any {
	if len(contents) == 0 {
		return contents
	}
	out := append([]any(nil), contents...)
	for len(out) > 2 && !fitsJSONWithContents(parent, out, maxBytes) {
		out = append(out[:1], out[2:]...)
	}
	for len(out) > 1 && !fitsJSONWithContents(parent, out, maxBytes) {
		out = out[1:]
	}
	if !fitsJSONWithContents(parent, out, maxBytes) {
		truncateStringLeaves(out, maxBytes)
	}
	return out
}

func fitsJSONWithContents(parent map[string]any, contents []any, maxBytes int) bool {
	parent["contents"] = contents
	return fitsJSON(parent, maxBytes)
}

func fitsJSON(v any, maxBytes int) bool {
	out, err := json.Marshal(v)
	return err == nil && len(out) <= maxBytes
}

func truncateStringLeaves(v any, maxBytes int) {
	switch t := v.(type) {
	case map[string]any:
		for key, val := range t {
			switch child := val.(type) {
			case string:
				t[key] = truncateUTF8(child, maxStringLeafBytes(maxBytes))
			default:
				truncateStringLeaves(child, maxBytes)
			}
		}
	case []any:
		for i := range t {
			switch child := t[i].(type) {
			case string:
				t[i] = truncateUTF8(child, maxStringLeafBytes(maxBytes))
			default:
				truncateStringLeaves(child, maxBytes)
			}
		}
	}
}

func maxStringLeafBytes(maxBytes int) int {
	const minLeaf = 256
	leaf := maxBytes / 4
	if leaf < minLeaf {
		return minLeaf
	}
	return leaf
}

func truncateUTF8(s string, maxBytes int) string {
	if maxBytes <= 0 || len(s) <= maxBytes {
		return s
	}
	if maxBytes <= len(truncatedSuffix) {
		return s[:maxBytes]
	}
	cut := maxBytes - len(truncatedSuffix)
	for cut > 0 && !utf8.ValidString(s[:cut]) {
		cut--
	}
	return s[:cut] + truncatedSuffix
}

func extractMultipartFileNames(body []byte, boundary string) string {
	if boundary == "" {
		return multipartPlaceholder
	}

	reader := multipart.NewReader(bytes.NewReader(body), boundary)
	result := make(map[string]interface{})

	for {
		part, err := reader.NextPart()
		if err != nil {
			break
		}

		filename := part.FileName()
		fieldname := part.FormName()

		if filename != "" {
			result[fieldname] = map[string]string{
				"_type":    "file",
				"filename": filename,
			}
		} else if fieldname != "" {
			result[fieldname] = redactedValue
		}
		_ = part.Close()
	}

	if len(result) == 0 {
		return multipartPlaceholder
	}

	jsonBytes, err := json.Marshal(result)
	if err != nil {
		return multipartPlaceholder
	}

	return string(jsonBytes)
}

func lookupHeader(headers map[string][]string, name string) string {
	for key, values := range headers {
		if strings.EqualFold(key, name) && len(values) > 0 {
			return values[0]
		}
	}
	return ""
}

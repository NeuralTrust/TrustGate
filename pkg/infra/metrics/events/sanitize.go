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
	"mime"
	"mime/multipart"
	"strings"
)

const (
	multipartPlaceholder = `{"_multipart": true}`
	truncatedSuffix      = "...[truncated]"

	maxSanitizedBodyBytes = 64 * 1024
	maxMultipartFieldValueBytes = 256

	redactedValue = "[REDACTED]"

	bearerRedacted = "Bearer " + redactedValue
	basicRedacted  = "Basic " + redactedValue
)

var credentialBodyKeys = map[string]struct{}{
	"password":       {},
	"passwd":           {},
	"secret":           {},
	"token":            {},
	"api_key":          {},
	"apikey":           {},
	"authorization":    {},
	"credential":       {},
	"access_token":     {},
	"refresh_token":    {},
	"client_secret":    {},
	"private_key":      {},
}

var sensitiveHeaders = map[string]struct{}{
	"authorization":         {},
	"proxy-authorization":   {},
	"www-authenticate":      {},
	"authentication":        {},
	"cookie":                {},
	"set-cookie":            {},
	"x-api-key":             {},
	"api-key":               {},
	"x-tg-api-key":          {},
	"x-ag-api-key":          {},
	"x-ag-playground-token": {},
	"x-auth-token":          {},
	"x-access-token":        {},
	"x-amz-security-token":  {},
	"x-amz-credential":      {},
	"x-goog-api-key":        {},
	"x-csrf-token":          {},
	"x-xsrf-token":          {},
}

// SanitizeBody returns a loggable representation of a request/response body.
func SanitizeBody(body []byte, headers map[string][]string) string {
	return sanitizeBody(body, headers, maxSanitizedBodyBytes)
}

// SanitizeBodyFull behaves like SanitizeBody but never truncates by size.
func SanitizeBodyFull(body []byte, headers map[string][]string) string {
	return sanitizeBody(body, headers, 0)
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
	return stripCredentialBodyValue(generic)
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
	if !containsCredentialKeys(generic) {
		return body
	}
	stripped := stripCredentialBodyValue(generic)
	out, err := json.Marshal(stripped)
	if err != nil {
		return body
	}
	return out
}

func containsCredentialKeys(v any) bool {
	switch t := v.(type) {
	case map[string]any:
		for key, val := range t {
			if isCredentialBodyKey(key) {
				return true
			}
			if containsCredentialKeys(val) {
				return true
			}
		}
	case []any:
		for _, val := range t {
			if containsCredentialKeys(val) {
				return true
			}
		}
	}
	return false
}

func stripCredentialBodyValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for key, val := range t {
			if isCredentialBodyKey(key) {
				t[key] = stripCredentialBodyLeaf(val)
			} else {
				t[key] = stripCredentialBodyValue(val)
			}
		}
		return t
	case []any:
		for i := range t {
			t[i] = stripCredentialBodyValue(t[i])
		}
		return t
	default:
		return v
	}
}

func stripCredentialBodyLeaf(v any) any {
	switch t := v.(type) {
	case string:
		return redactedValue
	case []any:
		for i := range t {
			t[i] = stripCredentialBodyLeaf(t[i])
		}
		return t
	case map[string]any:
		return stripCredentialBodyValue(t)
	default:
		return v
	}
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
	return string(body[:maxBytes]) + truncatedSuffix
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

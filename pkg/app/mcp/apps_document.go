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
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"

	segmentjson "github.com/segmentio/encoding/json"
)

const (
	appsDocumentMIME                                         = "text/html;profile=mcp-app"
	minAppsDocumentBytes, maxAppsDocumentBytes               = 64 * 1024, 2 * 1024 * 1024
	maxAppsJSONDepth, maxAppsJSONFields, maxAppsJSONKeyBytes = 64, 64, 128
	maxAppsJSONTokens                                        = 1024
)

var (
	// ErrInvalidAppsDocument identifies fail-closed MCP Apps document rejection.
	ErrInvalidAppsDocument = &AppsDocumentError{}
	errAppsDocument        = errors.New("invalid document")
)

// AppsDocumentReason is a bounded rejection category for protocol error mapping.
type AppsDocumentReason uint8

const (
	AppsDocumentPolicyReason AppsDocumentReason = iota
	AppsDocumentEnvelopeReason
	AppsDocumentSizeReason
	AppsDocumentEncodingReason
	AppsDocumentHTMLReason
)

// AppsDocumentError reports a bounded document rejection reason.
type AppsDocumentError struct{ Reason AppsDocumentReason }

func (e *AppsDocumentError) Error() string                { return "invalid MCP Apps document" }
func (e *AppsDocumentError) Is(target error) bool         { return target == ErrInvalidAppsDocument }
func invalidAppsDocument(reason AppsDocumentReason) error { return &AppsDocumentError{Reason: reason} }

// AppsDocumentEncoding identifies the decoded resource representation.
type AppsDocumentEncoding uint8

const (
	AppsDocumentTextEncoding AppsDocumentEncoding = iota
	AppsDocumentBlobEncoding
)

// AppsDocumentMetadata contains only bounded decoding metadata.
type AppsDocumentMetadata struct {
	Encoding    AppsDocumentEncoding
	DecodedSize int
}

type appsDecodedDocument struct {
	body     []byte
	metadata AppsDocumentMetadata
}

type appsDocumentWire struct {
	Contents []appsDocumentContent `json:"contents"`
	Meta     json.RawMessage       `json:"_meta"`
}

type appsDocumentContent struct {
	URI  json.RawMessage `json:"uri"`
	MIME json.RawMessage `json:"mimeType"`
	Text json.RawMessage `json:"text"`
	Blob json.RawMessage `json:"blob"`
	Meta json.RawMessage `json:"_meta"`
}

// ValidateAppsDocument decodes and structurally validates an MCP Apps document.
func ValidateAppsDocument(expectedURI string, maxBytes int, raw json.RawMessage) (AppsDocumentMetadata, error) {
	document, err := decodeAppsDocument(expectedURI, maxBytes, raw)
	if err != nil {
		return AppsDocumentMetadata{}, err
	}
	if validateAppsHTML(document.body) != nil {
		return AppsDocumentMetadata{}, invalidAppsDocument(AppsDocumentHTMLReason)
	}
	return document.metadata, nil
}

func decodeAppsDocument(expectedURI string, maxBytes int, raw json.RawMessage) (appsDecodedDocument, error) {
	if maxBytes < minAppsDocumentBytes || maxBytes > maxAppsDocumentBytes {
		return appsDecodedDocument{}, invalidAppsDocument(AppsDocumentPolicyReason)
	}
	if _, err := ValidateAppsURI(expectedURI); err != nil {
		return appsDecodedDocument{}, invalidAppsDocument(AppsDocumentPolicyReason)
	}
	if len(raw) > maxBytes*6+1024 || !utf8.Valid(raw) || validateAppsJSON(raw) != nil {
		return appsDecodedDocument{}, invalidAppsDocument(AppsDocumentEnvelopeReason)
	}
	var envelope appsDocumentWire
	flags := segmentjson.DisallowUnknownFields | segmentjson.DontCopyRawMessage | segmentjson.DontMatchCaseInsensitiveStructFields
	remaining, parseErr := segmentjson.Parse(raw, &envelope, flags)
	if parseErr != nil || len(remaining) != 0 || len(envelope.Contents) != 1 || !validAppsMeta(envelope.Meta) {
		return appsDecodedDocument{}, invalidAppsDocument(AppsDocumentEnvelopeReason)
	}
	content := envelope.Contents[0]
	uri, _, uriErr := decodeAppsJSONString(content.URI, maxAppsURIBytes)
	mime, _, mimeErr := decodeAppsJSONString(content.MIME, len(appsDocumentMIME))
	_, returnedURIErr := ValidateAppsURI(string(uri))
	if uriErr != nil || returnedURIErr != nil || string(uri) != expectedURI ||
		mimeErr != nil || string(mime) != appsDocumentMIME || !validAppsMeta(content.Meta) {
		return appsDecodedDocument{}, invalidAppsDocument(AppsDocumentEnvelopeReason)
	}
	hasText, hasBlob := content.Text != nil, content.Blob != nil
	if hasText == hasBlob {
		return appsDecodedDocument{}, invalidAppsDocument(AppsDocumentEnvelopeReason)
	}
	if hasText {
		return decodeAppsText(content.Text, maxBytes)
	}
	return decodeAppsBlob(content.Blob, maxBytes)
}

func validateAppsJSON(raw []byte) error {
	stack := make([]map[string]bool, 0, maxAppsJSONDepth)
	tokenizer := segmentjson.NewTokenizer(raw)
	tokens := 0
	for tokenizer.Next() {
		tokens++
		if tokens > maxAppsJSONTokens {
			return errAppsDocument
		}
		switch tokenizer.Delim {
		case '{':
			if len(stack) >= maxAppsJSONDepth {
				return errAppsDocument
			}
			stack = append(stack, map[string]bool{})
		case '[':
			if len(stack) >= maxAppsJSONDepth {
				return errAppsDocument
			}
			stack = append(stack, nil)
		case '}', ']':
			if len(stack) == 0 || tokenizer.Delim == '}' && stack[len(stack)-1] == nil ||
				tokenizer.Delim == ']' && stack[len(stack)-1] != nil {
				return errAppsDocument
			}
			stack = stack[:len(stack)-1]
		default:
			if tokenizer.IsKey {
				if len(stack) == 0 || stack[len(stack)-1] == nil ||
					len(tokenizer.Value) > maxAppsJSONKeyBytes*6+2 {
					return errAppsDocument
				}
				key := string(tokenizer.String())
				fields := stack[len(stack)-1]
				if len(key) > maxAppsJSONKeyBytes || fields[key] || len(fields) >= maxAppsJSONFields {
					return errAppsDocument
				}
				fields[key] = true
			}
		}
	}
	if tokenizer.Err != nil || len(stack) != 0 {
		return errAppsDocument
	}
	return nil
}

func validAppsMeta(raw []byte) bool {
	raw = bytes.TrimSpace(raw)
	return len(raw) == 0 || len(raw) > 1 && raw[0] == '{' && raw[len(raw)-1] == '}'
}

func decodeAppsJSONString(raw []byte, max int) ([]byte, bool, error) {
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' || !utf8.Valid(raw) {
		return nil, false, errAppsDocument
	}
	size, valid := appsJSONStringSize(raw, max)
	if !valid || size < 0 {
		return nil, false, errAppsDocument
	}
	if size > max {
		return nil, true, errAppsDocument
	}
	value := segmentjson.RawValue(raw).AppendUnquote(make([]byte, 0, size))
	if len(value) != size {
		return nil, false, errAppsDocument
	}
	return value, false, nil
}

func appsJSONStringSize(raw []byte, max int) (int, bool) {
	size := 0
	for i := 1; i < len(raw)-1; {
		if raw[i] != '\\' {
			_, width := utf8.DecodeRune(raw[i:])
			size, i = size+width, i+width
		} else if raw[i+1] != 'u' {
			size, i = size+1, i+2
		} else {
			if i+6 > len(raw)-1 {
				return 0, false
			}
			r, valid := appsHexRune(raw[i+2 : i+6])
			if !valid {
				return 0, false
			}
			i += 6
			if r >= 0xD800 && r <= 0xDBFF {
				if i+6 > len(raw)-1 || raw[i] != '\\' || raw[i+1] != 'u' {
					return 0, false
				}
				low, lowValid := appsHexRune(raw[i+2 : i+6])
				if !lowValid || low < 0xDC00 || low > 0xDFFF {
					return 0, false
				}
				size, i = size+4, i+6
				continue
			}
			width := utf8.RuneLen(r)
			if r >= 0xDC00 && r <= 0xDFFF || width < 0 {
				return 0, false
			}
			size += width
		}
		if size > max {
			return size, true
		}
	}
	return size, true
}

func appsHexRune(raw []byte) (rune, bool) {
	var value rune
	for _, current := range raw {
		var digit rune
		switch {
		case current >= '0' && current <= '9':
			digit = rune(current - '0')
		case current >= 'a' && current <= 'f':
			digit = rune(current-'a') + 10
		case current >= 'A' && current <= 'F':
			digit = rune(current-'A') + 10
		default:
			return 0, false
		}
		value = value*16 + digit
	}
	return value, true
}

func decodeAppsText(raw []byte, max int) (appsDecodedDocument, error) {
	body, oversized, err := decodeAppsJSONString(raw, max)
	if oversized {
		return appsDecodedDocument{}, invalidAppsDocument(AppsDocumentSizeReason)
	}
	if err != nil {
		return appsDecodedDocument{}, invalidAppsDocument(AppsDocumentEncodingReason)
	}
	return appsDecodedDocument{
		body: body,
		metadata: AppsDocumentMetadata{
			Encoding:    AppsDocumentTextEncoding,
			DecodedSize: len(body),
		},
	}, nil
}

func decodeAppsBlob(raw []byte, max int) (appsDecodedDocument, error) {
	value, oversized, err := decodeAppsJSONString(raw, base64.StdEncoding.EncodedLen(max))
	if oversized {
		return appsDecodedDocument{}, invalidAppsDocument(AppsDocumentSizeReason)
	}
	if err != nil || len(value)%4 != 0 || bytes.ContainsAny(value, " \t\r\n-_") {
		return appsDecodedDocument{}, invalidAppsDocument(AppsDocumentEncodingReason)
	}
	projected := base64.StdEncoding.DecodedLen(len(value))
	if bytes.HasSuffix(value, []byte("==")) {
		projected -= 2
	} else if bytes.HasSuffix(value, []byte("=")) {
		projected--
	}
	if projected > max {
		return appsDecodedDocument{}, invalidAppsDocument(AppsDocumentSizeReason)
	}
	var body bytes.Buffer
	decoder := base64.NewDecoder(base64.StdEncoding.Strict(), bytes.NewReader(value))
	n, decodeErr := io.Copy(&body, io.LimitReader(decoder, int64(max)+1))
	if n > int64(max) {
		return appsDecodedDocument{}, invalidAppsDocument(AppsDocumentSizeReason)
	}
	if decodeErr != nil || n != int64(projected) {
		return appsDecodedDocument{}, invalidAppsDocument(AppsDocumentEncodingReason)
	}
	return appsDecodedDocument{
		body: body.Bytes(),
		metadata: AppsDocumentMetadata{
			Encoding:    AppsDocumentBlobEncoding,
			DecodedSize: int(n),
		},
	}, nil
}

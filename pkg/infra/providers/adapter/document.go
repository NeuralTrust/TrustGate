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
	"encoding/base64"
	"net/url"
	"path"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	mediaTypeOctetStream = "application/octet-stream"
	mediaTypeTextPlain   = "text/plain"
	mediaTypePDF         = "application/pdf"
	defaultDocumentName  = "document"
	maxExtensionLen      = 5
	// Long filenames are cut so the name, plus any " (n)" suffix, stays well
	// inside what Bedrock accepts.
	maxConverseDocumentNameLen = 100
)

// documentExtensions names each common document media type by the extension
// Bedrock Converse uses as its document format.
var documentExtensions = map[string]string{
	"application/pdf":    "pdf",
	"text/plain":         "txt",
	"text/markdown":      "md",
	"text/x-markdown":    "md",
	"text/csv":           "csv",
	"text/html":          "html",
	"application/json":   "json",
	"application/msword": "doc",
	"application/vnd.openxmlformats-officedocument.wordprocessingml.document": "docx",
	"application/vnd.ms-excel": "xls",
	"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":         "xlsx",
	"application/vnd.ms-powerpoint":                                             "ppt",
	"application/vnd.openxmlformats-officedocument.presentationml.presentation": "pptx",
}

var extensionMediaTypes = map[string]string{
	"pdf":  "application/pdf",
	"txt":  "text/plain",
	"md":   "text/markdown",
	"csv":  "text/csv",
	"html": "text/html",
	"htm":  "text/html",
	"json": "application/json",
	"doc":  "application/msword",
	"docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
	"xls":  "application/vnd.ms-excel",
	"xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
	"ppt":  "application/vnd.ms-powerpoint",
	"pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
}

// fileExtension is the lowercase extension of name, or "" when the text after
// the last dot is not a short alphanumeric run: a title such as "Dr. Smith
// report" has a dot but no extension.
func fileExtension(name string) string {
	ext := strings.ToLower(strings.TrimPrefix(path.Ext(strings.TrimSpace(name)), "."))
	if ext == "" || len(ext) > maxExtensionLen {
		return ""
	}
	for _, r := range ext {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') {
			return ""
		}
	}
	return ext
}

func urlPath(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Path
}

// inferDocumentMediaType drops media type parameters and, when the client sent
// no type or a generic one, infers it from the filename extension. It returns
// "" when neither says anything.
func inferDocumentMediaType(mediaType, name string) string {
	mt, _, _ := strings.Cut(mediaType, ";")
	mt = strings.ToLower(strings.TrimSpace(mt))
	if mt != "" && mt != mediaTypeOctetStream {
		return mt
	}
	if inferred, ok := extensionMediaTypes[fileExtension(name)]; ok {
		return inferred
	}
	return mt
}

// normalizeDocumentMediaType is inferDocumentMediaType for inline data, whose
// targets all require a media type.
func normalizeDocumentMediaType(mediaType, name string) string {
	if mt := inferDocumentMediaType(mediaType, name); mt != "" {
		return mt
	}
	return mediaTypeOctetStream
}

// parseDocumentData reads a document payload as clients send it: a base64
// data URI, an http(s) URL, or bare base64.
func parseDocumentData(raw, mediaType, name string) CanonicalDocument {
	raw = strings.TrimSpace(raw)
	if rest, ok := strings.CutPrefix(raw, "data:"); ok {
		meta, data, ok := strings.Cut(rest, ",")
		params := strings.Split(meta, ";")
		if ok && data != "" && len(params) >= 2 && params[len(params)-1] == "base64" {
			if params[0] != "" {
				mediaType = params[0]
			}
			return CanonicalDocument{MediaType: normalizeDocumentMediaType(mediaType, name), Data: data, Name: name}
		}
		return CanonicalDocument{MediaType: inferDocumentMediaType(mediaType, name), URL: raw, Name: name}
	}
	if isHTTPImageURL(raw) {
		return CanonicalDocument{MediaType: inferDocumentMediaType(mediaType, firstNonEmptyString(name, urlPath(raw))), URL: raw, Name: name}
	}
	return CanonicalDocument{MediaType: normalizeDocumentMediaType(mediaType, name), Data: raw, Name: name}
}

func textDocument(text, mediaType, name string) CanonicalDocument {
	if mediaType == "" {
		mediaType = mediaTypeTextPlain
	}
	return CanonicalDocument{
		MediaType: normalizeDocumentMediaType(mediaType, name),
		Data:      base64.StdEncoding.EncodeToString([]byte(text)),
		Name:      name,
	}
}

func (d CanonicalDocument) dataURI() string {
	return "data:" + d.MediaType + ";base64," + d.Data
}

// text returns the decoded content of a textual document. Targets that only
// read text documents as text get it that way instead of as opaque bytes.
func (d CanonicalDocument) text() (string, bool) {
	if d.Data == "" || !isTextMediaType(d.MediaType) {
		return "", false
	}
	raw, err := decodeBase64(d.Data)
	if err != nil || !utf8.Valid(raw) {
		return "", false
	}
	return string(raw), true
}

func isTextMediaType(mt string) bool {
	return strings.HasPrefix(mt, "text/") || mt == "application/json"
}

// decodeBase64 accepts padded and unpadded standard base64, as SDKs send both.
func decodeBase64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if raw, err := base64.StdEncoding.DecodeString(s); err == nil {
		return raw, nil
	}
	return base64.RawStdEncoding.DecodeString(strings.TrimRight(s, "="))
}

// documentFormat is the Converse document format for d: the extension of its
// media type, else of its filename. Bedrock validates the format, so an
// unusual one is forwarded and rejected upstream rather than here.
func documentFormat(d CanonicalDocument) string {
	if ext, ok := documentExtensions[d.MediaType]; ok {
		return ext
	}
	if ext := fileExtension(d.Name); ext != "" {
		return ext
	}
	if strings.HasPrefix(d.MediaType, "text/") {
		return "txt"
	}
	return ""
}

// documentFilename is the client's filename, or a generic one carrying the
// extension of the media type, since some targets type a file by its name.
func documentFilename(d CanonicalDocument) string {
	name := strings.TrimSpace(d.Name)
	if name == "" {
		name = defaultDocumentName
	}
	if fileExtension(name) != "" {
		return name
	}
	if ext := documentFormat(d); ext != "" {
		return name + "." + ext
	}
	return name
}

// inClientOrder places a message's documents before or after its text the way
// the client sent them.
func inClientOrder[T any](documentsFirst bool, documents, text []T) []T {
	if documentsFirst {
		return append(documents, text...)
	}
	return append(text, documents...)
}

func documentMediaTypeForFormat(format string) string {
	if mt, ok := extensionMediaTypes[strings.ToLower(format)]; ok {
		return mt
	}
	return mediaTypeOctetStream
}

// converseDocumentNames hands out the document names of one Converse request.
// Bedrock allows only alphanumerics, single whitespace, hyphens, parentheses
// and square brackets in a name and rejects two documents with the same one.
type converseDocumentNames map[string]bool

func (used converseDocumentNames) next(filename string) string {
	base := strings.TrimSpace(filename)
	if ext := fileExtension(base); ext != "" {
		base = base[:len(base)-len(ext)-1]
	}
	var sb strings.Builder
	space := false
	for _, r := range base {
		switch {
		case r < utf8.RuneSelf && (r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'),
			r == '-', r == '(', r == ')', r == '[', r == ']':
			sb.WriteRune(r)
			space = false
		case r == ' ' || r == '\t':
			if !space && sb.Len() > 0 {
				sb.WriteByte(' ')
			}
			space = true
		default:
			sb.WriteByte('-')
			space = false
		}
	}
	name := sb.String()
	if len(name) > maxConverseDocumentNameLen {
		name = name[:maxConverseDocumentNameLen]
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = defaultDocumentName
	}
	candidate := name
	for n := 2; used[candidate]; n++ {
		candidate = name + " (" + strconv.Itoa(n) + ")"
	}
	used[candidate] = true
	return candidate
}

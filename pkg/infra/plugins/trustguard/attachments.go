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
	"encoding/json"
	"strings"
)

// extractPayloadAttachments walks provider request JSON for user file/image
// parts and returns Guard attachments for doc_analyzer → IPI.
func extractPayloadAttachments(rawBody []byte) []GuardAttachment {
	if len(rawBody) == 0 {
		return nil
	}
	var root map[string]any
	if json.Unmarshal(rawBody, &root) != nil {
		return nil
	}
	var out []GuardAttachment
	seen := map[string]struct{}{}
	add := func(a GuardAttachment) {
		key := a.ContentType + "|" + a.Filename + "|" + a.Data + "|" + a.URL
		if _, ok := seen[key]; ok {
			return
		}
		if strings.TrimSpace(a.Data) == "" && strings.TrimSpace(a.URL) == "" {
			return
		}
		seen[key] = struct{}{}
		out = append(out, a)
	}
	walkAttachmentValue(root["messages"], add)
	walkAttachmentValue(root["input"], add)
	walkAttachmentValue(root["contents"], add)
	return out
}

func walkAttachmentValue(v any, add func(GuardAttachment)) {
	switch t := v.(type) {
	case []any:
		for _, item := range t {
			walkAttachmentValue(item, add)
		}
	case map[string]any:
		role, _ := t["role"].(string)
		role = strings.ToLower(strings.TrimSpace(role))
		if role == "assistant" || role == "model" || role == "tool" || role == "system" || role == "developer" {
			return
		}
		if content, ok := t["content"]; ok {
			walkContentParts(content, add)
		}
		if parts, ok := t["parts"]; ok {
			walkContentParts(parts, add)
		}
		collectAttachmentPart(t, add)
	}
}

func walkContentParts(content any, add func(GuardAttachment)) {
	switch c := content.(type) {
	case []any:
		for _, part := range c {
			if m, ok := part.(map[string]any); ok {
				collectAttachmentPart(m, add)
			}
		}
	case map[string]any:
		collectAttachmentPart(c, add)
	}
}

func collectAttachmentPart(m map[string]any, add func(GuardAttachment)) {
	typ, _ := m["type"].(string)
	typ = strings.ToLower(strings.TrimSpace(typ))
	switch typ {
	case "image_url", "input_image":
		add(attachmentFromImageURL(m))
	case "image":
		add(attachmentFromAnthropicImage(m))
	case "file", "input_file", "document":
		add(attachmentFromFile(m))
	}
	if inline, ok := m["inlineData"].(map[string]any); ok {
		add(GuardAttachment{
			Filename:    "inline",
			ContentType: strAny(inline["mimeType"]),
			Data:        strAny(inline["data"]),
		})
	}
	if fd, ok := m["fileData"].(map[string]any); ok {
		add(GuardAttachment{
			Filename:    "file",
			ContentType: strAny(fd["mimeType"]),
			URL:         strAny(fd["fileUri"]),
		})
	}
}

func attachmentFromImageURL(m map[string]any) GuardAttachment {
	a := GuardAttachment{Filename: "image", ContentType: "image/*"}
	switch img := m["image_url"].(type) {
	case string:
		fillAttachmentURLOrData(&a, img)
	case map[string]any:
		fillAttachmentURLOrData(&a, strAny(img["url"]))
	}
	if u := strAny(m["image_url"]); a.URL == "" && a.Data == "" && u != "" {
		fillAttachmentURLOrData(&a, u)
	}
	if u := strAny(m["url"]); a.URL == "" && a.Data == "" {
		fillAttachmentURLOrData(&a, u)
	}
	return a
}

func attachmentFromAnthropicImage(m map[string]any) GuardAttachment {
	a := GuardAttachment{Filename: "image", ContentType: "image/*"}
	src, _ := m["source"].(map[string]any)
	if src == nil {
		return a
	}
	if mt := strAny(src["media_type"]); mt != "" {
		a.ContentType = mt
	}
	switch strings.ToLower(strAny(src["type"])) {
	case "base64":
		a.Data = strAny(src["data"])
	case "url":
		a.URL = strAny(src["url"])
	default:
		if d := strAny(src["data"]); d != "" {
			a.Data = d
		}
		if u := strAny(src["url"]); u != "" {
			a.URL = u
		}
	}
	return a
}

func attachmentFromFile(m map[string]any) GuardAttachment {
	a := GuardAttachment{
		Filename:    firstNonEmpty(strAny(m["filename"]), strAny(m["name"]), "file"),
		ContentType: firstNonEmpty(strAny(m["content_type"]), strAny(m["mime_type"]), "application/octet-stream"),
	}
	if fileObj, ok := m["file"].(map[string]any); ok {
		if a.Filename == "file" {
			a.Filename = firstNonEmpty(strAny(fileObj["filename"]), strAny(fileObj["name"]), "file")
		}
		if d := strAny(fileObj["file_data"]); d != "" {
			fillAttachmentURLOrData(&a, d)
		}
		if u := strAny(fileObj["file_id"]); u != "" && a.Data == "" && a.URL == "" {
			a.URL = u
		}
	}
	if d := strAny(m["file_data"]); d != "" {
		fillAttachmentURLOrData(&a, d)
	}
	if d := strAny(m["data"]); d != "" && a.Data == "" {
		a.Data = d
	}
	if u := strAny(m["url"]); u != "" && a.URL == "" {
		a.URL = u
	}
	if src, ok := m["source"].(map[string]any); ok {
		if mt := strAny(src["media_type"]); mt != "" {
			a.ContentType = mt
		}
		if d := strAny(src["data"]); d != "" {
			a.Data = d
		}
		if u := strAny(src["url"]); u != "" {
			a.URL = u
		}
	}
	return a
}

func fillAttachmentURLOrData(a *GuardAttachment, v string) {
	v = strings.TrimSpace(v)
	if v == "" {
		return
	}
	if strings.HasPrefix(v, "data:") {
		if i := strings.Index(v, ","); i >= 0 {
			meta := v[5:i]
			a.Data = v[i+1:]
			if j := strings.Index(meta, ";"); j >= 0 {
				a.ContentType = meta[:j]
			} else if meta != "" {
				a.ContentType = meta
			}
			return
		}
	}
	if strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") {
		a.URL = v
		return
	}
	a.Data = v
}

func strAny(v any) string {
	s, _ := v.(string)
	return strings.TrimSpace(s)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

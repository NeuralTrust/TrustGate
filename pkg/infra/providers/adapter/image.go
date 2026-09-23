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
	"errors"
	"net/url"
	"strings"
)

// ErrUnsupportedContent reports request content the target format cannot carry.
var ErrUnsupportedContent = errors.New("unsupported content")

func normalizeImageMediaType(mt string) string {
	mt = strings.ToLower(strings.TrimSpace(mt))
	if mt == "image/jpg" {
		return "image/jpeg"
	}
	return mt
}

func supportedImageMediaType(mt string) bool {
	switch mt {
	case "image/jpeg", "image/png", "image/gif", "image/webp":
		return true
	default:
		return false
	}
}

func parseImageURL(raw, detail string) CanonicalImage {
	rest, ok := strings.CutPrefix(raw, "data:")
	if !ok {
		return CanonicalImage{URL: raw, Detail: detail}
	}
	meta, data, ok := strings.Cut(rest, ",")
	if !ok || data == "" {
		return CanonicalImage{URL: raw, Detail: detail}
	}
	params := strings.Split(meta, ";")
	if len(params) < 2 || params[len(params)-1] != "base64" {
		return CanonicalImage{URL: raw, Detail: detail}
	}
	mediaType := normalizeImageMediaType(params[0])
	if mediaType == "" {
		return CanonicalImage{URL: raw, Detail: detail}
	}
	return CanonicalImage{
		MediaType: mediaType,
		Data:      data,
		Detail:    detail,
	}
}

func (img CanonicalImage) dataURI() string {
	if img.Data != "" {
		return "data:" + img.MediaType + ";base64," + img.Data
	}
	return img.URL
}

func isHTTPImageURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

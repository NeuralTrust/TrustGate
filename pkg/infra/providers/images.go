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

package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
)

const (
	RouteImagesGenerations = "/v1/images/generations"
	RouteImagesEdits       = "/v1/images/edits"
	RouteImagesVariations  = "/v1/images/variations"
)

type ImagesRequest struct {
	Method      string
	Path        string
	Query       url.Values
	ContentType string
	Body        []byte
}

type ImagesResult struct {
	Body        []byte
	ContentType string
}

type ImagesClient interface {
	Images(ctx context.Context, config *Config, req ImagesRequest) (*ImagesResult, error)
}

func IsImagesPath(path string) bool {
	switch path {
	case RouteImagesGenerations, RouteImagesEdits, RouteImagesVariations:
		return true
	default:
		return false
	}
}

func ValidateImagesMethod(method, path string) error {
	if method == http.MethodPost && IsImagesPath(path) {
		return nil
	}
	return fmt.Errorf("method %s is not allowed for %s", method, path)
}

func JoinOpenAIImagesURL(baseURL, gatewayPath string, query url.Values) string {
	base := strings.TrimRight(baseURL, "/")
	suffix := strings.TrimPrefix(gatewayPath, "/v1")
	if !strings.HasPrefix(suffix, "/images/") {
		suffix = "/images/generations"
	}
	return appendQuery(base+suffix, query)
}

func JoinOpenRouterImagesURL(baseURL, gatewayPath string, query url.Values) string {
	return appendQuery(strings.TrimRight(baseURL, "/")+OpenRouterImagesPath(gatewayPath), query)
}

func OpenRouterImagesPath(gatewayPath string) string {
	switch gatewayPath {
	case RouteImagesEdits:
		return "/images/edits"
	case RouteImagesVariations:
		return "/images/variations"
	default:
		return "/images"
	}
}

func AzureImagesOperation(gatewayPath string) string {
	switch gatewayPath {
	case RouteImagesEdits:
		return "images/edits"
	case RouteImagesVariations:
		return "images/variations"
	default:
		return "images/generations"
	}
}

func IsImagesMultipart(contentType string) bool {
	if contentType == "" {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return strings.HasPrefix(strings.ToLower(contentType), "multipart/")
	}
	return strings.HasPrefix(mediaType, "multipart/")
}

func ExtractImagesModel(contentType string, body []byte) string {
	if IsImagesMultipart(contentType) {
		return extractMultipartField(contentType, body, "model")
	}
	var probe struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return ""
	}
	return probe.Model
}

func extractMultipartField(contentType string, body []byte, name string) string {
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return ""
	}
	boundary := params["boundary"]
	if boundary == "" {
		return ""
	}
	reader := multipart.NewReader(bytes.NewReader(body), boundary)
	for {
		part, err := reader.NextPart()
		if err != nil {
			return ""
		}
		if part.FormName() != name {
			_, _ = io.Copy(io.Discard, part)
			_ = part.Close()
			continue
		}
		value, err := io.ReadAll(part)
		_ = part.Close()
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(value))
	}
}

func appendQuery(endpoint string, query url.Values) string {
	if enc := query.Encode(); enc != "" {
		return endpoint + "?" + enc
	}
	return endpoint
}

func ImagesResultFromFiles(result *FilesResult, err error) (*ImagesResult, error) {
	if err != nil {
		return nil, err
	}
	if result == nil {
		return &ImagesResult{}, nil
	}
	return &ImagesResult{Body: result.Body, ContentType: result.ContentType}, nil
}

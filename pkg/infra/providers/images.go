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
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

const RouteImagesGenerations = "/v1/images/generations"

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
	return path == RouteImagesGenerations
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
	base := strings.TrimRight(baseURL, "/")
	path := "/images"
	if gatewayPath != "" && gatewayPath != RouteImagesGenerations {
		suffix := strings.TrimPrefix(gatewayPath, "/v1")
		if strings.HasPrefix(suffix, "/images/") {
			path = "/images"
		}
	}
	return appendQuery(base+path, query)
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

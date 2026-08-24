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
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

type FilesRequest struct {
	Method      string
	Path        string
	Query       url.Values
	ContentType string
	Body        []byte
}

type FilesResult struct {
	Body        []byte
	ContentType string
}

type FilesClient interface {
	Files(ctx context.Context, config *Config, req FilesRequest) (*FilesResult, error)
}

type FilesIDFamily string

const (
	FilesIDFamilyUnknown   FilesIDFamily = ""
	FilesIDFamilyOpenAI    FilesIDFamily = "openai"
	FilesIDFamilyAnthropic FilesIDFamily = "anthropic"
)

func IsFilesPath(path string) bool {
	if path == "/v1/files" {
		return true
	}
	if !strings.HasPrefix(path, "/v1/files/") {
		return false
	}
	tail := strings.TrimPrefix(path, "/v1/files/")
	if tail == "" {
		return false
	}
	id, extra, found := strings.Cut(tail, "/")
	if id == "" {
		return false
	}
	if !found {
		return true
	}
	return extra == "content"
}

func filesRestPath(path string) string {
	if IsFilesPath(path) {
		return path
	}
	rest := RestAfterConsumerSlug(path)
	if IsFilesPath(rest) {
		return rest
	}
	return ""
}

func FilesIDFromPath(path string) string {
	rest := filesRestPath(path)
	if rest == "" || rest == "/v1/files" {
		return ""
	}
	tail := strings.TrimPrefix(rest, "/v1/files/")
	id, _, _ := strings.Cut(tail, "/")
	if decoded, err := url.PathUnescape(id); err == nil {
		return decoded
	}
	return id
}

func ClassifyFilesID(id string) FilesIDFamily {
	switch {
	case id == "":
		return FilesIDFamilyUnknown
	case strings.HasPrefix(id, "file_"):
		return FilesIDFamilyAnthropic
	case strings.HasPrefix(id, "file-"):
		return FilesIDFamilyOpenAI
	default:
		return FilesIDFamilyUnknown
	}
}

func filesIDFamilyForProvider(provider string) FilesIDFamily {
	if !SupportsCapability(provider, CapabilityFiles) {
		return FilesIDFamilyUnknown
	}
	if provider == ProviderAnthropic {
		return FilesIDFamilyAnthropic
	}
	return FilesIDFamilyOpenAI
}

func ProviderMatchesFilesID(provider, fileID string) bool {
	family := ClassifyFilesID(fileID)
	switch family {
	case FilesIDFamilyUnknown:
		return true
	case FilesIDFamilyOpenAI, FilesIDFamilyAnthropic:
		return filesIDFamilyForProvider(provider) == family
	default:
		return false
	}
}

func ValidateFilesMethod(method, path string) error {
	switch method {
	case http.MethodGet:
		if IsFilesPath(path) {
			return nil
		}
	case http.MethodPost:
		if path == "/v1/files" {
			return nil
		}
	case http.MethodDelete:
		if IsFilesPath(path) && path != "/v1/files" && !strings.HasSuffix(path, "/content") {
			return nil
		}
	}
	return fmt.Errorf("method %s is not allowed for %s", method, path)
}

func JoinOpenAIFilesURL(baseURL, gatewayPath string, query url.Values) string {
	base := strings.TrimRight(baseURL, "/")
	suffix := strings.TrimPrefix(gatewayPath, "/v1")
	if !strings.HasPrefix(suffix, "/files") {
		suffix = "/files"
	}
	out := base + suffix
	if enc := query.Encode(); enc != "" {
		return out + "?" + enc
	}
	return out
}

func JoinAzureFilesURL(endpoint, gatewayPath, apiVersion string, query url.Values) string {
	base := strings.TrimRight(endpoint, "/")
	suffix := strings.TrimPrefix(gatewayPath, "/v1")
	if !strings.HasPrefix(suffix, "/files") {
		suffix = "/files"
	}
	out := base + "/openai" + suffix
	q := url.Values{}
	for key, values := range query {
		for _, value := range values {
			q.Add(key, value)
		}
	}
	if apiVersion != "" {
		q.Set("api-version", apiVersion)
	}
	if enc := q.Encode(); enc != "" {
		return out + "?" + enc
	}
	return out
}

func RestAfterConsumerSlug(path string) string {
	trimmed := strings.TrimPrefix(path, "/")
	_, rest, found := strings.Cut(trimmed, "/")
	if !found || rest == "" {
		return ""
	}
	return strings.TrimRight("/"+rest, "/")
}

func DoFilesHTTP(
	ctx context.Context,
	httpClient *http.Client,
	method, endpoint, contentType string,
	body []byte,
	applyAuth func(*http.Request),
) (*FilesResult, error) {
	var reader io.Reader
	if len(body) > 0 {
		reader = bytes.NewReader(body)
	}
	httpReq, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	if contentType != "" {
		httpReq.Header.Set("Content-Type", contentType)
	}
	if applyAuth != nil {
		applyAuth(httpReq)
	}

	resp, err := httpClient.Do(httpReq) // #nosec G704 -- endpoint is built from admin-configured provider URLs
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	if registry.IsHTTPError(resp.StatusCode) {
		return nil, registry.NewBackendHTTPError(resp.StatusCode, buf.Bytes(), resp.Header)
	}
	ct := resp.Header.Get("Content-Type")
	if ct == "" {
		ct = "application/json"
	}
	return &FilesResult{Body: buf.Bytes(), ContentType: ct}, nil
}

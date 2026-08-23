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
	"encoding/base64"
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
	RouteAudioSpeech          = "/v1/audio/speech"
	RouteAudioTranscriptions  = "/v1/audio/transcriptions"
	azureAudioSpeechOp        = "audio/speech"
	azureAudioTranscriptionOp = "audio/transcriptions"
)

type AudioRequest struct {
	Method      string
	Path        string
	Query       url.Values
	ContentType string
	Body        []byte
}

type AudioResult struct {
	Body        []byte
	ContentType string
}

type AudioSpeechClient interface {
	AudioSpeech(ctx context.Context, config *Config, req AudioRequest) (*AudioResult, error)
}

type AudioTranscriptionClient interface {
	AudioTranscription(ctx context.Context, config *Config, req AudioRequest) (*AudioResult, error)
}

func IsAudioPath(path string) bool {
	switch path {
	case RouteAudioSpeech, RouteAudioTranscriptions:
		return true
	default:
		return false
	}
}

func IsAudioSpeechPath(path string) bool {
	return path == RouteAudioSpeech
}

func IsAudioTranscriptionPath(path string) bool {
	return path == RouteAudioTranscriptions
}

func ValidateAudioMethod(method, path string) error {
	if method == http.MethodPost && IsAudioPath(path) {
		return nil
	}
	return fmt.Errorf("method %s is not allowed for %s", method, path)
}

func JoinOpenAIAudioURL(baseURL, gatewayPath string, query url.Values) string {
	base := strings.TrimRight(baseURL, "/")
	suffix := strings.TrimPrefix(gatewayPath, "/v1")
	if !strings.HasPrefix(suffix, "/audio/") {
		suffix = "/audio/speech"
	}
	return appendQuery(base+suffix, query)
}

func AzureAudioOperation(gatewayPath string) string {
	if gatewayPath == RouteAudioTranscriptions {
		return azureAudioTranscriptionOp
	}
	return azureAudioSpeechOp
}

func IsAudioMultipart(contentType string) bool {
	if contentType == "" {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return strings.HasPrefix(strings.ToLower(contentType), "multipart/")
	}
	return strings.HasPrefix(mediaType, "multipart/")
}

func ExtractAudioModel(contentType string, body []byte) string {
	if IsAudioMultipart(contentType) {
		return extractMultipartField(contentType, body, "model")
	}
	return extractJSONStringField(body, "model")
}

func MapSpeechVoiceToVoiceID(body []byte) []byte {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return body
	}
	if _, ok := raw["voice_id"]; ok {
		return body
	}
	voice, ok := raw["voice"]
	if !ok {
		return body
	}
	raw["voice_id"] = voice
	out, err := json.Marshal(raw)
	if err != nil {
		return body
	}
	return out
}

func AudioContentTypeForFormat(format string) string {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "mp3":
		return "audio/mpeg"
	case "wav":
		return "audio/wav"
	case "pcm":
		return "audio/pcm"
	case "flac":
		return "audio/flac"
	case "opus", "ogg":
		return "audio/ogg"
	default:
		return "audio/mpeg"
	}
}

func UnwrapJSONSpeechAudio(result *AudioResult, err error, requestBody []byte) (*AudioResult, error) {
	if err != nil || result == nil {
		return result, err
	}
	if isAudioMediaType(result.ContentType) {
		return result, nil
	}
	var probe struct {
		AudioData string `json:"audio_data"`
	}
	if json.Unmarshal(result.Body, &probe) != nil || probe.AudioData == "" {
		return result, nil
	}
	decoded, decErr := base64.StdEncoding.DecodeString(probe.AudioData)
	if decErr != nil {
		return nil, fmt.Errorf("speech audio_data: %w", decErr)
	}
	return &AudioResult{
		Body:        decoded,
		ContentType: AudioContentTypeForFormat(extractJSONStringField(requestBody, "response_format")),
	}, nil
}

func AudioResultFromFiles(result *FilesResult, err error) (*AudioResult, error) {
	if err != nil {
		return nil, err
	}
	if result == nil {
		return &AudioResult{}, nil
	}
	return &AudioResult{Body: result.Body, ContentType: result.ContentType}, nil
}

func extractJSONStringField(body []byte, name string) string {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return ""
	}
	value, ok := raw[name]
	if !ok {
		return ""
	}
	var out string
	if err := json.Unmarshal(value, &out); err != nil {
		return ""
	}
	return out
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

func isAudioMediaType(contentType string) bool {
	if contentType == "" {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return strings.HasPrefix(strings.ToLower(contentType), "audio/")
	}
	return strings.HasPrefix(mediaType, "audio/")
}

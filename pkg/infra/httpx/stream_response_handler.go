package httpx

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/factory"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/sirupsen/logrus"
)

// injectStreamTrue sets "stream": true in a JSON request body so that upstreams
// using OpenAI-style API (openai, azure) actually use streaming when the agent
// format (e.g. Gemini) does not include stream in the body.
func injectStreamTrue(body []byte) []byte {
	var m map[string]interface{}
	if err := json.Unmarshal(body, &m); err != nil {
		return body
	}
	m["stream"] = true
	out, err := json.Marshal(m)
	if err != nil {
		return body
	}
	return out
}

// HandleProviderStream handles streaming responses from a provider upstream,
// including cross-provider format adaptation and payload forwarding to both
// the metrics channel (streamResponse) and the plugin channel (via fiber locals).
func HandleProviderStream(
	logger *logrus.Logger,
	providerLocator factory.ProviderLocator,
	adapterRegistry *adapter.Registry,
	req *types.RequestContext,
	target *types.UpstreamTargetDTO,
	streamResponse chan []byte,
) (*types.ResponseContext, error) {

	providerClient, err := providerLocator.Get(target.Provider)
	if err != nil {
		return nil, fmt.Errorf("failed to get streaming provider client: %w", err)
	}

	sourceFormat := adapter.Format(req.SourceFormat)
	targetFormat := adapter.ResolveTargetFormat(target.Provider, target.ProviderOptions)
	needsAdapt := !adapter.IsSameWireFormat(sourceFormat, targetFormat)

	body := req.Body
	if needsAdapt {
		body, err = adapterRegistry.AdaptRequest(req.Body, sourceFormat, targetFormat)
		if err != nil {
			return nil, fmt.Errorf("failed to adapt stream request (%s->%s): %w", sourceFormat, targetFormat, err)
		}
	}

	if adapter.IsSameWireFormat(targetFormat, adapter.FormatOpenAI) {
		body = adapter.NormalizeOpenAIRequest(body)
	}

	body, _, err = adapter.ValidateModel(body, target.Models, target.DefaultModel)
	if err != nil {
		logger.WithError(err).Warn("model validation failed, proceeding with original body")
		body = req.Body
	}

	if adapter.IsSameWireFormat(targetFormat, adapter.FormatOpenAI) ||
		targetFormat == adapter.FormatOpenAIResponses ||
		targetFormat == adapter.FormatAnthropic ||
		targetFormat == adapter.FormatMistral {
		body = injectStreamTrue(body)
	}

	streamChan := make(chan []byte)
	errChan := make(chan error, 1)
	breakChan := make(chan struct{}, 1)

	req.C.Set("Content-Type", "text/event-stream")
	req.C.Set("Cache-Control", "no-cache")
	req.C.Set("Connection", "keep-alive")
	req.C.Set("X-Accel-Buffering", "no")
	req.C.Set("X-Selected-Provider", target.Provider)

	go func() {
		defer close(streamChan)
		err := providerClient.CompletionsStream(
			req,
			&providers.Config{
				Options:       target.ProviderOptions,
				AllowedModels: target.Models,
				DefaultModel:  target.DefaultModel,
				Credentials: providers.Credentials{
					ApiKey: target.Credentials.ApiKey,
					AwsBedrock: &providers.AwsBedrock{
						Region:       target.Credentials.AWSRegion,
						SecretKey:    target.Credentials.AWSSecretAccessKey,
						AccessKey:    target.Credentials.AWSAccessKeyID,
						SessionToken: target.Credentials.AWSSessionToken,
						UseRole:      target.Credentials.AWSUseRole,
						RoleARN:      target.Credentials.AWSRole,
					},
				},
			},
			body,
			streamChan,
			breakChan,
		)
		if err != nil {
			logger.WithError(err).Error("failed to stream request")
			errChan <- err
			return
		}
		close(errChan)
	}()

	select {
	case err := <-errChan:
		if err != nil {
			return nil, fmt.Errorf("failed to stream request: %w", err)
		}
	case <-req.C.Context().Done():
		return nil, fmt.Errorf("request cancelled: %w", req.C.Context().Err())
	case <-breakChan:
		break
	case <-time.After(30 * time.Second):
		break
	}

	streamFile := openDebugFile(logger, sourceFormat, targetFormat)

	fwd := newPayloadForwarder(req, streamResponse)

	req.C.Context().SetBodyStreamWriter(func(w *bufio.Writer) {
		defer close(streamResponse)
		if streamFile != nil {
			defer func() { _ = streamFile.Close() }()
		}
		defer fwd.Close()

		writeLine := func(line []byte) {
			_, _ = w.Write(line)
			_, _ = w.Write(newlineBytes)
			if streamFile != nil {
				_, _ = streamFile.Write(line)
				_, _ = streamFile.Write(newlineBytes)
			}
		}
		writeAdaptedLines := func(lines [][]byte) {
			for _, line := range lines {
				writeLine(line)
			}
			_ = w.Flush()
			for _, line := range lines {
				if bytes.HasPrefix(line, sseDataPrefix) {
					mp := bytes.TrimSpace(bytes.TrimPrefix(line, sseDataPrefix))
					if len(mp) > 0 {
						fwd.Send(mp)
					}
				}
			}
		}

		var acc toolCallAccumulator
		for msg := range streamChan {
			if needsAdapt {
				processAdaptedChunk(logger, adapterRegistry, msg, sourceFormat, targetFormat, fwd, &acc, writeAdaptedLines)
				continue
			}

			if bytes.HasPrefix(msg, sseDataPrefix) {
				payload := bytes.TrimSpace(bytes.TrimPrefix(msg, sseDataPrefix))
				if len(payload) > 0 && !bytes.Equal(payload, sseDoneMarker) {
					fwd.Send(payload)
				}
			}
			writeLine(msg)
			_ = w.Flush()
		}
	})

	return &types.ResponseContext{
		StatusCode: http.StatusOK,
		Streaming:  true,
		Metadata:   req.Metadata,
		Target:     target,
	}, nil
}

// openDebugFile creates a debug SSE file when TG_SAVE_STREAM_DEBUG is set.
func openDebugFile(logger *logrus.Logger, source, target adapter.Format) *os.File {
	if os.Getenv("TG_SAVE_STREAM_DEBUG") != "true" {
		return nil
	}
	dir := "streams"
	_ = os.MkdirAll(dir, 0750)
	ts := time.Now().Format("20060102-150405")
	name := fmt.Sprintf("%s_%s_%s.sse", string(target), string(source), ts)
	path := filepath.Join(dir, name)
	f, err := os.Create(path) // #nosec G304
	if err != nil {
		logger.WithError(err).Warn("could not create stream debug file")
		return nil
	}
	logger.WithField("path", path).Info("saving stream response to file")
	return f
}

// processAdaptedChunk handles a single upstream message that needs cross-provider
// format adaptation before being written to the client.
func processAdaptedChunk(
	logger *logrus.Logger,
	registry *adapter.Registry,
	msg []byte,
	sourceFormat, targetFormat adapter.Format,
	fwd *payloadForwarder,
	acc *toolCallAccumulator,
	writeAdaptedLines func([][]byte),
) {
	if !bytes.HasPrefix(msg, sseDataPrefix) {
		return
	}
	payload := bytes.TrimSpace(bytes.TrimPrefix(msg, sseDataPrefix))
	if len(payload) == 0 || bytes.Equal(payload, sseDoneMarker) {
		return
	}

	fwd.SendToPluginsOnly(payload)

	// Gemini agent + upstream with incremental tool_calls: decode, accumulate, encode.
	if sourceFormat == adapter.FormatGemini &&
		(adapter.IsSameWireFormat(targetFormat, adapter.FormatOpenAI) ||
			targetFormat == adapter.FormatOpenAIResponses ||
			targetFormat == adapter.FormatAnthropic ||
			targetFormat == adapter.FormatMistral) {
		processGeminiToolCallAdaptation(logger, registry, payload, sourceFormat, targetFormat, acc, writeAdaptedLines)
		return
	}

	adaptedLines, adaptErr := registry.AdaptStreamChunk(payload, sourceFormat, targetFormat)
	if adaptErr != nil {
		logger.WithError(adaptErr).
			WithField("payload_preview", string(truncatePreview(payload))).
			Warn("stream adapt chunk failed")
		return
	}
	if len(adaptedLines) == 0 {
		if logger.GetLevel() == logrus.DebugLevel {
			logger.
				WithField("payload_preview", string(truncatePreview(payload))).
				WithField("source", sourceFormat).
				WithField("target", targetFormat).
				Debug("stream chunk skipped (empty adapted result)")
		}
		return
	}
	writeAdaptedLines(adaptedLines)
}

// processGeminiToolCallAdaptation decodes an upstream chunk, accumulates tool call
// deltas, and encodes them in Gemini format when finished.
func processGeminiToolCallAdaptation(
	logger *logrus.Logger,
	registry *adapter.Registry,
	payload []byte,
	sourceFormat, targetFormat adapter.Format,
	acc *toolCallAccumulator,
	writeAdaptedLines func([][]byte),
) {
	canonical, decErr := registry.DecodeStreamChunkFor(payload, targetFormat)
	if decErr != nil {
		logger.WithError(decErr).
			WithField("payload_preview", string(truncatePreview(payload))).
			Warn("stream decode chunk failed")
		return
	}
	if canonical == nil {
		return
	}

	acc.Merge(canonical.ToolCallDeltas)

	if canonical.Role != "" {
		encodeAndWrite(registry, &adapter.CanonicalStreamChunk{Role: canonical.Role}, sourceFormat, writeAdaptedLines)
	}
	if canonical.Delta != "" {
		encodeAndWrite(registry, &adapter.CanonicalStreamChunk{Delta: canonical.Delta}, sourceFormat, writeAdaptedLines)
	}
	if canonical.FinishReason != "" && len(*acc) > 0 {
		encodeAndWrite(registry, &adapter.CanonicalStreamChunk{ToolCallDeltas: acc.Flush()}, sourceFormat, writeAdaptedLines)
	}
	if canonical.FinishReason != "" {
		encodeAndWrite(registry, &adapter.CanonicalStreamChunk{FinishReason: canonical.FinishReason}, sourceFormat, writeAdaptedLines)
	}
}

func encodeAndWrite(registry *adapter.Registry, chunk *adapter.CanonicalStreamChunk, format adapter.Format, write func([][]byte)) {
	lines, err := registry.EncodeStreamChunkFor(chunk, format)
	if err == nil && len(lines) > 0 {
		write(lines)
	}
}

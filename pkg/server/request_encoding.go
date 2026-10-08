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

package server

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"io"
	"log/slog"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	"github.com/gofiber/fiber/v2"
	"github.com/valyala/fasthttp"
)

// maxConcurrentDecodes bounds how many request bodies are decompressed at once,
// so the memory decoding can claim stays near maxConcurrentDecodes*limit.
const maxConcurrentDecodes = 32

const decodeChunk = 32 << 10

var (
	errChainedEncoding     = errors.New("chained content encodings are not supported")
	errUnsupportedEncoding = errors.New("unsupported content encoding")
	errDecodedTooLarge     = errors.New("decoded body exceeds the limit")
)

var decoders = map[string]func(io.Reader) (io.ReadCloser, error){
	"gzip":    func(r io.Reader) (io.ReadCloser, error) { return gzip.NewReader(r) },
	"x-gzip":  func(r io.Reader) (io.ReadCloser, error) { return gzip.NewReader(r) },
	"deflate": zlib.NewReader,
}

func decodeRequestBody(limit int, logger *slog.Logger) fiber.Handler {
	return decodeRequestBodyWith(limit, maxConcurrentDecodes, logger)
}

func decodeRequestBodyWith(limit, concurrency int, logger *slog.Logger) fiber.Handler {
	slots := make(chan struct{}, concurrency)
	return func(c *fiber.Ctx) error {
		req := c.Request()
		coding, err := requestContentCoding(&req.Header)
		if err != nil {
			return reject(c, logger, fiber.StatusUnsupportedMediaType, "unsupported_content_encoding", err.Error(), coding)
		}
		if coding == "" || len(req.Body()) == 0 {
			req.Header.Del(fiber.HeaderContentEncoding)
			return c.Next()
		}

		select {
		case slots <- struct{}{}:
		default:
			c.Set(fiber.HeaderRetryAfter, "1")
			return reject(c, logger, fiber.StatusServiceUnavailable, "decoder_busy", "too many compressed requests in flight", coding)
		}
		body, err := decodeBody(req.Body(), decoders[coding], limit)
		<-slots
		switch {
		case errors.Is(err, errDecodedTooLarge):
			return reject(c, logger, fiber.StatusRequestEntityTooLarge, "request_too_large", "request body too large", coding)
		case err != nil:
			return reject(c, logger, fiber.StatusBadRequest, "invalid_compressed_body", "invalid compressed request body", coding)
		}

		req.SetBodyRaw(body)
		req.Header.Del(fiber.HeaderContentEncoding)
		req.Header.SetContentLength(len(body))
		return c.Next()
	}
}

func requestContentCoding(h *fasthttp.RequestHeader) (string, error) {
	var codings []string
	for key, value := range h.All() {
		if !strings.EqualFold(string(key), fiber.HeaderContentEncoding) {
			continue
		}
		for part := range strings.SplitSeq(string(value), ",") {
			part = strings.ToLower(strings.TrimSpace(part))
			if part != "" && part != "identity" {
				codings = append(codings, part)
			}
		}
	}
	switch {
	case len(codings) == 0:
		return "", nil
	case len(codings) > 1:
		return strings.Join(codings, ","), errChainedEncoding
	case decoders[codings[0]] == nil:
		return codings[0], errUnsupportedEncoding
	default:
		return codings[0], nil
	}
}

// decodeBody never holds more than limit+1 decoded bytes, whatever the
// compression ratio of the input.
func decodeBody(raw []byte, open func(io.Reader) (io.ReadCloser, error), limit int) ([]byte, error) {
	r, err := open(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	defer func() { _ = r.Close() }()

	out := make([]byte, 0, min(limit+1, max(decodeChunk, 4*len(raw))))
	for {
		if len(out) == cap(out) {
			if cap(out) > limit {
				return nil, errDecodedTooLarge
			}
			grown := make([]byte, len(out), min(limit+1, 2*cap(out)))
			copy(grown, out)
			out = grown
		}
		n, err := r.Read(out[len(out):cap(out)])
		out = out[:len(out)+n]
		if errors.Is(err, io.EOF) {
			if len(out) > limit {
				return nil, errDecodedTooLarge
			}
			return out, nil
		}
		if err != nil {
			return nil, err
		}
	}
}

func reject(c *fiber.Ctx, logger *slog.Logger, status int, code, message, coding string) error {
	if logger != nil {
		logger.Warn("request body decoding rejected",
			slog.Int("status", status),
			slog.String("reason", code),
			slog.String("content_encoding", coding),
			slog.String("method", c.Method()),
			slog.String("path", c.Path()),
			slog.String("remote_ip", c.IP()),
		)
	}
	return c.Status(status).JSON(httpio.ErrorBody{Error: code, Message: message})
}

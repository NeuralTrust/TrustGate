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
	"errors"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/valyala/fasthttp"
)

var (
	errChainedEncoding     = errors.New("chained content encodings are not supported")
	errUnsupportedEncoding = errors.New("unsupported content encoding")
)

// decodeRequestBody decodes at most one content coding, bounded by limit, so
// downstream handlers always see an identity body.
func decodeRequestBody(limit int) fiber.Handler {
	return func(c *fiber.Ctx) error {
		req := c.Request()
		coding, err := requestContentCoding(&req.Header)
		if err != nil {
			return c.Status(fiber.StatusUnsupportedMediaType).JSON(fiber.Map{"error": err.Error()})
		}
		if coding == "" {
			req.Header.Del(fiber.HeaderContentEncoding)
			return c.Next()
		}

		body, err := decodeBody(req, coding, limit)
		if err != nil {
			if errors.Is(err, fasthttp.ErrBodyTooLarge) {
				return c.Status(fiber.StatusRequestEntityTooLarge).JSON(fiber.Map{"error": "request body too large"})
			}
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid compressed request body"})
		}

		req.SetBody(body)
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
	switch len(codings) {
	case 0:
		return "", nil
	case 1:
		switch codings[0] {
		case "gzip", "x-gzip", "deflate", "br":
			return codings[0], nil
		}
		return "", errUnsupportedEncoding
	default:
		return "", errChainedEncoding
	}
}

func decodeBody(req *fasthttp.Request, coding string, limit int) ([]byte, error) {
	switch coding {
	case "gzip", "x-gzip":
		return req.BodyGunzipWithLimit(limit)
	case "deflate":
		return req.BodyInflateWithLimit(limit)
	default:
		return req.BodyUnbrotliWithLimit(limit)
	}
}

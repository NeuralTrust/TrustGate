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

package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"time"
)

const (
	maxResponseBytes    = 8 << 20
	maxCatalogBytes     = 16 << 20
	maxCatalogItems     = 10000
	maxCatalogPages     = 100
	sessionCloseTimeout = 5 * time.Second
)

// ErrResponseTooLarge reports an upstream response or SSE event exceeding the memory budget.
var ErrResponseTooLarge = errors.New("MCP upstream response exceeds the size limit")

// ErrCatalogTooLarge reports discovery exceeding its cumulative memory or pagination budget.
var ErrCatalogTooLarge = errors.New("MCP upstream catalog exceeds the discovery limit")

var errRepeatedCursor = errors.New("MCP upstream repeated a pagination cursor")

type responseCancelKey struct{}

type boundedResponseBody struct {
	io.ReadCloser
	limit    int
	size     int
	sse      bool
	lineSize int
	failed   bool
	cancel   context.CancelCauseFunc
}

func (b *boundedResponseBody) Read(p []byte) (int, error) {
	if b.failed {
		return 0, ErrResponseTooLarge
	}
	if !b.sse && len(p) > b.limit-b.size+1 {
		p = p[:b.limit-b.size+1]
	}
	n, err := b.ReadCloser.Read(p)
	if !b.sse {
		remaining := b.limit - b.size
		b.size += n
		if n > remaining {
			b.fail()
			return remaining, ErrResponseTooLarge
		}
		return n, err
	}
	for offset := 0; offset < n; {
		data := p[offset:n]
		newline := bytes.IndexByte(data, '\n')
		length := len(data)
		if newline >= 0 {
			length = newline + 1
		}
		remaining := b.limit - b.size
		b.size += length
		if length > remaining {
			b.fail()
			return offset + remaining, ErrResponseTooLarge
		}
		line := data[:length]
		if newline >= 0 {
			line = line[:length-1]
		}
		if len(bytes.Trim(line, "\r")) != 0 {
			b.lineSize = 1
		}
		// Match the SDK scanner's LF boundaries; bare CR must not reset its unbounded line buffer.
		if newline >= 0 {
			if b.lineSize == 0 {
				b.size = 0
			}
			b.lineSize = 0
		}
		offset += length
	}

	return n, err
}

func (b *boundedResponseBody) fail() {
	b.failed = true
	if b.cancel != nil {
		b.cancel(ErrResponseTooLarge)
	}
}

func boundResponse(resp *http.Response, req *http.Request) {
	if resp.Body == nil {
		return
	}
	contentType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	cancel, _ := req.Context().Value(responseCancelKey{}).(context.CancelCauseFunc)
	resp.Body = &boundedResponseBody{
		ReadCloser: resp.Body, limit: maxResponseBytes,
		sse: contentType == "text/event-stream" && resp.StatusCode >= 200 && resp.StatusCode < 300, cancel: cancel,
	}
}

func collectPages[T any](ctx context.Context, fetch func(string) ([]T, string, error)) ([]T, error) {
	var out []T
	seen := map[string]struct{}{"": {}}
	cursor, size := "", 0
	for page := 0; page < maxCatalogPages; page++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		items, next, err := fetch(cursor)
		if err != nil {
			return nil, err
		}
		if len(items) > maxCatalogItems-len(out) {
			return nil, ErrCatalogTooLarge
		}
		raw, err := json.Marshal(items)
		if err != nil {
			return nil, err
		}
		size += len(raw) + len(next)
		if size > maxCatalogBytes {
			return nil, ErrCatalogTooLarge
		}
		out = append(out, items...)
		if next == "" {
			return out, nil
		}
		if _, repeated := seen[next]; repeated {
			return nil, errRepeatedCursor
		}
		seen[next] = struct{}{}
		cursor = next
	}
	return nil, ErrCatalogTooLarge
}

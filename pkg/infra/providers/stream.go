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
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"iter"
	"strings"
	"time"
)

// StreamTimeout bounds the total duration of a single streamed response.
const StreamTimeout = 5 * time.Minute

func StreamResponse(ctx context.Context, rc io.ReadCloser) iter.Seq2[[]byte, error] {
	streamCtx, cancel := context.WithTimeout(ctx, StreamTimeout)
	return StreamSSE(streamCtx, &cancelOnCloseBody{ReadCloser: rc, cancel: cancel})
}

type cancelOnCloseBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b *cancelOnCloseBody) Close() error {
	b.cancel()
	return b.ReadCloser.Close()
}

func StreamSSE(ctx context.Context, rc io.ReadCloser) iter.Seq2[[]byte, error] {
	return func(yield func([]byte, error) bool) {
		defer func() { _ = rc.Close() }()

		sc := bufio.NewScanner(rc)
		buf := make([]byte, 0, 512*1024)
		sc.Buffer(buf, 2*1024*1024)

		for sc.Scan() {
			if err := ctx.Err(); err != nil {
				yield(nil, err)
				return
			}

			// Copy: the Scanner reuses its internal buffer.
			line := append([]byte(nil), sc.Bytes()...)

			if !yield(line, nil) {
				return
			}

			if err := ctx.Err(); err != nil {
				yield(nil, err)
				return
			}

			// OpenAI/Azure end-of-stream marker.
			if bytes.HasPrefix(line, []byte("data:")) {
				payload := bytes.TrimSpace(bytes.TrimPrefix(line, []byte("data:")))
				if bytes.Equal(payload, []byte("[DONE]")) {
					return
				}
			}
		}

		if err := sc.Err(); err != nil {
			if isBenignStreamEnd(err) {
				return
			}
			yield(nil, fmt.Errorf("sse scanner error: %w", err))
		}
	}
}

func isBenignStreamEnd(err error) bool {
	if errors.Is(err, io.EOF) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "use of closed network connection") ||
		strings.Contains(msg, "connection reset by peer")
}

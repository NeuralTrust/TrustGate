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
	"time"
)

// StreamTimeout bounds the total duration of a single streamed response,
// counted from its response headers, whether or not the upstream keeps
// sending.
const StreamTimeout = 5 * time.Minute

// StreamResponse reads rc as an SSE stream that ends with a
// context.DeadlineExceeded error once StreamTimeout has passed, even while a
// read of rc is blocked.
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

// StreamSSE reads rc line by line until [DONE], EOF or ctx ends. rc is closed
// as soon as ctx ends so that a read blocked on a silent upstream returns, and
// the stream then ends with the context's error.
//
// The [DONE] line is followed by the empty line that ends its event, and then
// the sequence ends without reading further. On the wire that blank line comes
// after the data line, but the read stops at [DONE], so the upstream's own
// separator is never read: yielding one here is what keeps the event whole for
// a same-format client, whose lines are relayed verbatim. Without it the client
// got "data: [DONE]\n" and nothing after, and a strict SSE parser drops an event
// that the stream ends before dispatching. The separator is yielded once, here,
// and never in addition to the upstream's, since that one is never read.
//
// Only a clean end of the body ends the sequence without an error. A read that
// fails while ctx is still live is the upstream going away mid-response,
// whatever the error says, so it is yielded: a connection reset by the peer
// truncates the answer exactly as any other transport failure does, and ending
// quietly on it let a cut-off response reach the client as a complete one. A
// read that fails because ctx ended, which closes rc and makes the read fail
// with "use of closed network connection", ends with the context's error
// instead, as before.
func StreamSSE(ctx context.Context, rc io.ReadCloser) iter.Seq2[[]byte, error] {
	return func(yield func([]byte, error) bool) {
		defer func() { _ = rc.Close() }()
		stopClosing := context.AfterFunc(ctx, func() { _ = rc.Close() })
		defer stopClosing()

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
					yield([]byte{}, nil)
					return
				}
			}
		}

		// ctx is checked first: once it has ended, rc was closed under the
		// read, and the read's error says so rather than why.
		if err := ctx.Err(); err != nil {
			yield(nil, err)
			return
		}
		if err := sc.Err(); err != nil {
			if isBenignStreamEnd(err) {
				return
			}
			yield(nil, fmt.Errorf("sse scanner error: %w", err))
		}
	}
}

// isBenignStreamEnd reports whether a read error is the body ending cleanly.
// bufio.Scanner already folds a bare io.EOF into a nil Err, so this only sees
// one a reader wrapped. A connection reset or a closed connection is not
// benign: StreamSSE checks ctx before calling it, so a closed connection seen
// here was not closed by us, and a reset is the upstream abandoning the
// response.
func isBenignStreamEnd(err error) bool {
	return errors.Is(err, io.EOF)
}

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

package mcp

import (
	"bufio"
	"errors"
	"fmt"
)

// ErrFrameTooLarge reports a frame the configured event bound cannot carry. The
// stream terminates on it rather than emitting a truncated frame, because a
// half-written JSON-RPC envelope is indistinguishable from a corrupt transport.
var ErrFrameTooLarge = errors.New("mcp: subscription frame exceeds the maximum event size")

const (
	sseEventField   = "event: message\n"
	sseDataField    = "data: "
	sseCommentField = ": "
	sseKeepalive    = "keepalive"
)

// frameSink is the narrow write surface a lease needs. The loop is written
// against it so every framing and ordering assertion is a unit test with no
// fasthttp connection behind it.
type frameSink interface {
	Frame(payload []byte) error
	Comment(text string) error
	Flush() error
}

// bufioSink writes SSE frames onto a fixed-size buffered writer. The buffer
// never grows, so a peer that stops reading blocks on Flush instead of
// accumulating frames in memory.
type bufioSink struct {
	w        *bufio.Writer
	maxBytes int
}

// newBufioSink wraps the fasthttp body-stream writer. A non-positive bound falls
// back to the configured default so a misconfigured value cannot disable the
// bound entirely.
func newBufioSink(w *bufio.Writer, maxBytes int) *bufioSink {
	if maxBytes <= 0 {
		maxBytes = defaultSubscriptionMaxEventBytes
	}
	return &bufioSink{w: w, maxBytes: maxBytes}
}

// Frame writes one SSE message event carrying payload as a single data line.
// The event name is written explicitly even though an unnamed event defaults to
// "message", because an explicit name is byte-checkable. No id field is ever
// written: an SSE id is a resumption cursor the client may replay through
// Last-Event-ID, and a stateless gateway holds no history to replay.
func (s *bufioSink) Frame(payload []byte) error {
	size := len(sseEventField) + len(sseDataField) + len(payload) + 2
	if size > s.maxBytes {
		return fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, size)
	}
	if _, err := s.w.WriteString(sseEventField); err != nil {
		return fmt.Errorf("writing subscription event field: %w", err)
	}
	if _, err := s.w.WriteString(sseDataField); err != nil {
		return fmt.Errorf("writing subscription data field: %w", err)
	}
	if _, err := s.w.Write(payload); err != nil {
		return fmt.Errorf("writing subscription payload: %w", err)
	}
	if _, err := s.w.WriteString("\n\n"); err != nil {
		return fmt.Errorf("terminating subscription frame: %w", err)
	}
	return nil
}

// Comment writes an SSE comment, which every conforming client scanner drops.
func (s *bufioSink) Comment(text string) error {
	size := len(sseCommentField) + len(text) + 2
	if size > s.maxBytes {
		return fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, size)
	}
	if _, err := s.w.WriteString(sseCommentField); err != nil {
		return fmt.Errorf("writing subscription comment field: %w", err)
	}
	if _, err := s.w.WriteString(text); err != nil {
		return fmt.Errorf("writing subscription comment: %w", err)
	}
	if _, err := s.w.WriteString("\n\n"); err != nil {
		return fmt.Errorf("terminating subscription comment: %w", err)
	}
	return nil
}

// Flush pushes the buffered frames onto the socket. It does not reset the
// fasthttp write deadline, which is why a lease is bounded well below it.
func (s *bufioSink) Flush() error {
	if err := s.w.Flush(); err != nil {
		return fmt.Errorf("flushing subscription frame: %w", err)
	}
	return nil
}

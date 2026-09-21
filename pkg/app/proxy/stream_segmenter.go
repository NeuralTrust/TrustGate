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

package proxy

import (
	"bytes"
)

// streamEvent is one whole SSE event: its original lines in arrival order.
// Anthropic, Cohere and Responses frame an event across several lines, so the
// event, not the line, is the unit that can be held and released without
// corrupting the wire.
type streamEvent struct {
	lines [][]byte
}

// segmenter assembles raw SSE lines into whole events. It is pure: no I/O, no
// plugin calls, no timers. It never re-encodes: an event carries the bytes it
// arrived as, because passthrough is byte-exact by contract and a re-encode
// would reorder usage, provider extensions and comments on the wire.
//
// Ownership: a line fed in is handed over, not copied, and comes back out in
// streamEvent.lines unchanged. The caller must feed lines it will not mutate or
// reuse afterwards, and must not mutate the lines it gets back. Every producer
// in the chain allocates per line today (providers/stream.go:62, the
// cross-format path, stream_toolcall_coalesce.go:71-73); a future one that
// reuses a scratch buffer would silently corrupt held blocks, and no test can
// catch it from the outside.
type segmenter struct {
	buf [][]byte
}

func newSegmenter() *segmenter {
	return &segmenter{}
}

// feed accumulates one raw SSE line and returns a whole event once the event is
// complete, or nil while it is still open. The line is handed over under the
// ownership contract on segmenter.
func (s *segmenter) feed(line []byte) *streamEvent {
	standalone := len(s.buf) == 0 && isSSEComment(line)
	s.buf = append(s.buf, line)
	if !standalone && len(bytes.TrimSpace(line)) != 0 {
		return nil
	}
	return s.flush()
}

// flush exists for the end of the stream and for providers that omit the last
// separator.
func (s *segmenter) flush() *streamEvent {
	if len(s.buf) == 0 {
		return nil
	}
	ev := &streamEvent{lines: s.buf}
	s.buf = nil
	return ev
}

func isSSEComment(line []byte) bool {
	return len(line) > 0 && line[0] == ':'
}

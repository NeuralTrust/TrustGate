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

package adapter

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream"
)

const (
	// BedrockFrameMaxBytes bounds one eventstream frame: Bedrock caps a
	// payload at 16 MiB, and the prelude, headers and checksums take a little
	// more.
	BedrockFrameMaxBytes = 16<<20 + 128<<10

	bedrockFramePrelude = 12
	bedrockFrameMin     = bedrockFramePrelude + 4

	headerAmznInputTokens  = "X-Amzn-Bedrock-Input-Token-Count"  // #nosec G101 -- header name, not a credential
	headerAmznOutputTokens = "X-Amzn-Bedrock-Output-Token-Count" // #nosec G101 -- header name, not a credential
	headerAmznCacheRead    = "X-Amzn-Bedrock-Cache-Read-Input-Token-Count"
	headerAmznCacheWrite   = "X-Amzn-Bedrock-Cache-Write-Input-Token-Count"

	eventHeaderMessageType   = ":message-type"
	eventHeaderEventType     = ":event-type"
	eventHeaderExceptionType = ":exception-type"
	eventHeaderContentType   = ":content-type"
	eventMessageTypeEvent    = "event"
	eventMessageTypeError    = "exception"
	eventTypeInvokeChunk     = "chunk"
)

var (
	// ErrBedrockFrameTooLarge reports a frame whose declared length exceeds the cap.
	ErrBedrockFrameTooLarge = errors.New("bedrock event stream frame exceeds the size limit")
	// ErrBedrockFrameMalformed reports a prelude that cannot start a frame.
	ErrBedrockFrameMalformed = errors.New("bedrock event stream frame is malformed")
)

// ReadBedrockFrame reads one complete eventstream frame from r and returns its
// bytes exactly as they arrived, prelude and checksums included. It returns
// io.EOF when r ends on a frame boundary and io.ErrUnexpectedEOF when it ends
// inside one. Checksums are not verified: the frame is relayed, and
// BedrockFrameView verifies the copy it decodes.
func ReadBedrockFrame(r io.Reader, limit int) ([]byte, error) {
	var prelude [bedrockFramePrelude]byte
	if _, err := io.ReadFull(r, prelude[:]); err != nil {
		return nil, err
	}
	total := binary.BigEndian.Uint32(prelude[:4])
	switch {
	case total < bedrockFrameMin:
		return nil, ErrBedrockFrameMalformed
	case limit < 0 || int64(total) > int64(limit):
		return nil, ErrBedrockFrameTooLarge
	}
	frame := make([]byte, total)
	copy(frame, prelude[:])
	if _, err := io.ReadFull(r, frame[bedrockFramePrelude:]); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return frame, nil
}

// BedrockFrameView decodes a raw frame into the SSE-style lines the stream
// observers and post_response read: "data: {...}" lines in the shape
// BedrockAdapter and the InvokeModel view decode. It never feeds the bytes
// sent to the client. A frame that fails its checksum, an exception frame and
// an event with no usable payload give no lines.
//
// A ConverseStream event becomes {"<eventType>": <payload>}, the way the
// Bedrock REST API frames it. An InvokeModelWithResponseStream chunk carries
// the model's own JSON base64-encoded; that JSON is the line.
func BedrockFrameView(raw []byte) [][]byte {
	msg, err := eventstream.NewDecoder().Decode(bytes.NewReader(raw), nil)
	if err != nil || headerString(msg.Headers, eventHeaderMessageType) != eventMessageTypeEvent {
		return nil
	}
	eventType := headerString(msg.Headers, eventHeaderEventType)
	if eventType == "" || !json.Valid(msg.Payload) {
		return nil
	}
	if eventType == eventTypeInvokeChunk {
		var chunk struct {
			Bytes []byte `json:"bytes"`
		}
		if json.Unmarshal(msg.Payload, &chunk) != nil || len(chunk.Bytes) == 0 {
			return nil
		}
		return [][]byte{append([]byte("data: "), chunk.Bytes...)}
	}
	key, err := json.Marshal(eventType)
	if err != nil {
		return nil
	}
	line := append([]byte("data: {"), key...)
	line = append(line, ':')
	line = append(line, msg.Payload...)
	line = append(line, '}')
	return [][]byte{line}
}

func headerString(headers eventstream.Headers, name string) string {
	if v := headers.Get(name); v != nil {
		return v.String()
	}
	return ""
}

// BedrockExceptionFrame encodes the exception frame Bedrock itself sends when
// a stream fails after its 200 went out, such as "internalServerException".
// SDK clients raise the matching typed error from it.
func BedrockExceptionFrame(exceptionType, message string) []byte {
	payload, _ := json.Marshal(map[string]string{"message": message})
	var headers eventstream.Headers
	headers.Set(eventHeaderMessageType, eventstream.StringValue(eventMessageTypeError))
	headers.Set(eventHeaderExceptionType, eventstream.StringValue(exceptionType))
	headers.Set(eventHeaderContentType, eventstream.StringValue("application/json"))
	var buf bytes.Buffer
	if err := eventstream.NewEncoder().Encode(&buf, eventstream.Message{Headers: headers, Payload: payload}); err != nil {
		return nil
	}
	return buf.Bytes()
}

// BedrockUsageFromHeaders reads the token accounting InvokeModel returns in
// response headers, since the model-native body may carry none. It returns nil
// when neither header is present.
func BedrockUsageFromHeaders(h http.Header) *CanonicalUsage {
	in, _ := strconv.Atoi(h.Get(headerAmznInputTokens))
	out, _ := strconv.Atoi(h.Get(headerAmznOutputTokens))
	read, _ := strconv.Atoi(h.Get(headerAmznCacheRead))
	write, _ := strconv.Atoi(h.Get(headerAmznCacheWrite))
	// The cache buckets are reported beside the plain input count, as they are
	// in Converse, and a canonical input count holds all three.
	usage := newCanonicalUsage(in+read+write, out, 0)
	if usage == nil {
		return nil
	}
	usage.setCache(read, write, 0)
	return usage
}

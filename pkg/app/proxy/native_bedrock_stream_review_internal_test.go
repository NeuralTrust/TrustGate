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
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func chunkFrame(t *testing.T, inner string) []byte {
	t.Helper()
	return testEventFrame(t, "chunk", `{"bytes":"`+base64.StdEncoding.EncodeToString([]byte(inner))+`"}`)
}

// releasedText is every string the client would read out of the frames, decoded
// the way an SDK decodes them, tool input fragments included.
func releasedText(t *testing.T, frames [][]byte) string {
	t.Helper()
	var all strings.Builder
	for _, f := range frames {
		p := decodeFrameText(t, f)
		all.WriteString(p)
		if strings.Contains(p, `"bytes"`) {
			var b struct {
				Bytes []byte `json:"bytes"`
			}
			require.NoError(t, json.Unmarshal([]byte(p), &b))
			all.Write(b.Bytes)
		}
	}
	return all.String()
}

// Reasoning arrives as JSON fragments that no text mask can edit, so a mask on a
// window that holds any fails open: the frames go through as they came.
func TestNativeStreamGuard_MaskWithReasoningInTheWindowFailsOpen(t *testing.T) {
	t.Parallel()
	for name, frames := range map[string][][]byte{
		"converse reasoning": {
			testEventFrame(t, "messageStart", `{"role":"assistant"}`),
			testEventFrame(t, "contentBlockDelta", `{"contentBlockIndex":0,"delta":{"reasoningContent":{"text":"thinking about `+streamEmail+`"}}}`),
			deltaFrame(t, "I will write to "+streamEmail+" now"),
			testEventFrame(t, "messageStop", `{"stopReason":"end_turn"}`),
		},
		"anthropic invoke thinking": {
			chunkFrame(t, `{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"thinking about `+streamEmail+`"}}`),
			chunkFrame(t, `{"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"I will write to `+streamEmail+` now"}}`),
			chunkFrame(t, `{"type":"message_delta","delta":{"stop_reason":"end_turn"}}`),
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			runner := &maskRunner{from: streamEmail, to: "<EMAIL>"}
			g := nativeGuardFor(runner, streamGuardConfig{headChars: 1000, minChars: 1000, maxHold: time.Hour})
			got, pe, rt := runNativeGuardTraced(t, g, frames)
			require.Nil(t, pe)
			requireStreamFailedOpen(t, got, frames, rt, "reasoning_not_maskable")
		})
	}
}

// Tool input released before the window is part of what the stream has said: a
// mask that decides on removed text that the arguments already carry cuts.
func TestNativeStreamGuard_MaskedTextAlreadyInReleasedToolInputFailsOpen(t *testing.T) {
	t.Parallel()
	frames := [][]byte{
		testEventFrame(t, "contentBlockStart", `{"contentBlockIndex":0,"start":{"toolUse":{"toolUseId":"t1","name":"send"}}}`),
		testEventFrame(t, "contentBlockDelta", `{"contentBlockIndex":0,"delta":{"toolUse":{"input":"{\"to\":\"bob\\u0040x.io\"}"}}}`),
		testEventFrame(t, "contentBlockStop", `{"contentBlockIndex":0}`),
		deltaFrame(t, "Done, I wrote to "+streamEmail+" for you"),
		deltaFrame(t, " and that is all"),
	}
	// A policy that reads text only: the tool input is released as it came.
	runner := &textOnlyMaskRunner{maskRunner{from: streamEmail, to: "<EMAIL>"}}
	got, pe, rt := runNativeGuardTraced(t, nativeGuardFor(runner, streamGuardConfig{headChars: 5, minChars: 1, maxHold: time.Hour}), frames)
	require.Nil(t, pe)
	requireStreamFailedOpen(t, got, frames, rt, "already_released_input")
}

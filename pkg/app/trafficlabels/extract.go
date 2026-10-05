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

package trafficlabels

import (
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/NeuralTrust/TrustGate/pkg/domain/trafficlabel"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

const roleUser = "user"

func userText(decoder RequestDecoder, body []byte, format adapter.Format, window int) string {
	return windowText(userMessages(decoder, body, format), window)
}

func userMessages(decoder RequestDecoder, body []byte, format adapter.Format) []string {
	if len(body) == 0 || decoder == nil {
		return nil
	}
	if format == "" {
		format = adapter.DetectFormat(body)
	}
	creq, err := decoder.DecodeRequestFor(body, format)
	if err != nil || creq == nil {
		return nil
	}
	var out []string
	for _, msg := range creq.Messages {
		if msg.Role != roleUser {
			continue
		}
		if content := strings.TrimSpace(msg.Content); content != "" {
			out = append(out, content)
		}
	}
	return out
}

func windowText(msgs []string, window int) string {
	return truncateTail(lastUserMessages(msgs, window), trafficlabel.MaxTextChars)
}

func lastUserMessages(msgs []string, window int) string {
	if window <= 0 || len(msgs) == 0 {
		return ""
	}
	return strings.Join(msgs[max(len(msgs)-window, 0):], "\n")
}

// capConversation keeps the most recent user messages a conversation buffer
// may hold: at most MaxMessageWindow messages and MaxTextChars runes in total,
// dropping the oldest first and trimming the head of a single oversized one.
func capConversation(msgs []string) []string {
	msgs = msgs[max(len(msgs)-trafficlabel.MaxMessageWindow, 0):]
	total := 0
	for i := len(msgs) - 1; i >= 0; i-- {
		n := utf8.RuneCountInString(msgs[i])
		if total+n <= trafficlabel.MaxTextChars {
			total += n
			continue
		}
		if i == len(msgs)-1 {
			return []string{truncateTail(msgs[i], trafficlabel.MaxTextChars)}
		}
		return slices.Clone(msgs[i+1:])
	}
	return slices.Clone(msgs)
}

func truncateTail(s string, limit int) string {
	if utf8.RuneCountInString(s) <= limit {
		return s
	}
	runes := []rune(s)
	return string(runes[len(runes)-limit:])
}

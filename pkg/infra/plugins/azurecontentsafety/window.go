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

package azurecontentsafety

import (
	"strings"
	"unicode/utf8"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

const turnSeparator = "\n"

// conversationWindow is the part of a conversation sent to text:analyze.
type conversationWindow struct {
	Text string
	// LeftOut is how many code points of the conversation are not in Text.
	LeftOut int
	// LastUserTooLarge says the last user message alone is above the limit, so
	// no window can hold it whole.
	LastUserTooLarge bool
}

// windowOf selects what to send when a conversation does not fit one call. It is
// the conversation's most recent maxTextCodePoints code points, always holding
// the whole last user message: when the tail does not reach back to that
// message, the window is the message followed by the most recent of what came
// after it. A conversation that fits is returned whole.
func windowOf(creq *adapter.CanonicalRequest) conversationWindow {
	parts, lastUser := conversationParts(creq)
	total := 0
	for i, part := range parts {
		if i > 0 {
			total += len(turnSeparator)
		}
		total += runeCount(part)
	}
	if total <= maxTextCodePoints {
		return conversationWindow{Text: strings.Join(parts, turnSeparator)}
	}
	if lastUser >= 0 && runeCount(parts[lastUser]) > maxTextCodePoints {
		return conversationWindow{LastUserTooLarge: true}
	}

	tail := []rune(strings.Join(parts, turnSeparator))
	text := string(tail[len(tail)-maxTextCodePoints:])
	if lastUser >= 0 {
		start := 0
		for i := 0; i < lastUser; i++ {
			start += runeCount(parts[i]) + len(turnSeparator)
		}
		if start < len(tail)-maxTextCodePoints {
			user := []rune(parts[lastUser])
			after := tail[start+len(user):]
			room := maxTextCodePoints - len(user) - len(turnSeparator)
			if room < 0 {
				room = 0
			}
			if room > len(after) {
				room = len(after)
			}
			text = string(user) + turnSeparator + string(after[len(after)-room:])
		}
	}
	return conversationWindow{Text: text, LeftOut: total - runeCount(text)}
}

// conversationParts is the system prompt and every non-empty message in order,
// and the index of the last user message among them (-1 when there is none).
func conversationParts(creq *adapter.CanonicalRequest) (parts []string, lastUser int) {
	lastUser = -1
	parts = make([]string, 0, len(creq.Messages)+1)
	if strings.TrimSpace(creq.System) != "" {
		parts = append(parts, creq.System)
	}
	for _, msg := range creq.Messages {
		if strings.TrimSpace(msg.Content) == "" {
			continue
		}
		if msg.Role == "user" {
			lastUser = len(parts)
		}
		parts = append(parts, msg.Content)
	}
	return parts, lastUser
}

func runeCount(s string) int { return utf8.RuneCountInString(s) }

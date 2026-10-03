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
	if len(body) == 0 || decoder == nil {
		return ""
	}
	if format == "" {
		format = adapter.DetectFormat(body)
	}
	creq, err := decoder.DecodeRequestFor(body, format)
	if err != nil || creq == nil {
		return ""
	}
	return truncateTail(lastUserMessages(creq.Messages, window), trafficlabel.MaxTextChars)
}

func lastUserMessages(msgs []adapter.CanonicalMessage, window int) string {
	if window <= 0 {
		return ""
	}
	picked := make([]string, 0, window)
	for i := len(msgs) - 1; i >= 0 && len(picked) < window; i-- {
		if msgs[i].Role != roleUser {
			continue
		}
		if content := strings.TrimSpace(msgs[i].Content); content != "" {
			picked = append(picked, content)
		}
	}
	slices.Reverse(picked)
	return strings.Join(picked, "\n")
}

func truncateTail(s string, limit int) string {
	if utf8.RuneCountInString(s) <= limit {
		return s
	}
	runes := []rune(s)
	return string(runes[len(runes)-limit:])
}

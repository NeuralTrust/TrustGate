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

package topicguard

type topicDefinition struct {
	Name       string `json:"name"`
	Definition string `json:"definition"`
}

type classifyRequest struct {
	Input     []string          `json:"input"`
	Topics    []topicDefinition `json:"topics"`
	Threshold *float64          `json:"threshold,omitempty"`
}

type topicScore struct {
	Topic       string  `json:"topic"`
	Probability float64 `json:"probability"`
	Blocked     bool    `json:"blocked"`
}

type classifyResponse struct {
	TopicScores   map[string]topicScore `json:"topic_scores"`
	BlockedTopics []string              `json:"blocked_topics"`
	NWindows      int                   `json:"n_windows"`
}

type configResponse struct {
	Name              string  `json:"name"`
	Revision          *string `json:"revision"`
	CandidateRevision *string `json:"candidate_revision"`
}

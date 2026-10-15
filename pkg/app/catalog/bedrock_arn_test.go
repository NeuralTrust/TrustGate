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

package catalog

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	arnFoundation = "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-sonnet-4-5-20250929-v1:0"
	arnSystemUS   = "arn:aws:bedrock:us-east-1:123456789012:inference-profile/us.anthropic.claude-sonnet-4-5-20250929-v1:0"
	arnSystemEU   = "arn:aws:bedrock:eu-west-1:123456789012:inference-profile/eu.anthropic.claude-sonnet-4-5-20250929-v1:0"
	arnSystemGlob = "arn:aws:bedrock:us-east-1:123456789012:inference-profile/global.anthropic.claude-sonnet-4-5-20250929-v1:0"
	arnApp        = "arn:aws:bedrock:us-east-1:123456789012:application-inference-profile/abc123xyz"
	arnProv       = "arn:aws:bedrock:us-east-1:123456789012:provisioned-model/pt1234"
	baseModel     = "anthropic.claude-sonnet-4-5-20250929-v1:0"
)

func TestSlugCandidates_BedrockARNsReachTheModel(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want string // a candidate that must be present
	}{
		{"foundation model ARN", arnFoundation, baseModel},
		{"system profile ARN us.", arnSystemUS, baseModel},
		{"system profile ARN eu.", arnSystemEU, baseModel},
		{"system profile ARN global.", arnSystemGlob, baseModel},
		{"china partition", "arn:aws-cn:bedrock:cn-north-1::foundation-model/" + baseModel, baseModel},
		{"gov partition", "arn:aws-us-gov:bedrock:us-gov-west-1:123456789012:inference-profile/us-gov." + baseModel, baseModel},
		{"plain global profile ID", "global." + baseModel, baseModel},
		{"plain us profile ID", "us." + baseModel, baseModel},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Contains(t, SlugCandidates(tc.in), tc.want)
		})
	}
}

func TestSlugCandidates_GlobalTwinKeepsBothCandidates(t *testing.T) {
	t.Parallel()
	got := SlugCandidates("global." + baseModel)
	assert.Equal(t, []string{"global." + baseModel, baseModel}, got, "the catalog's global twin is tried first, the bare ID second")
}

func TestSlugCandidates_ARNsThatNameNoModel(t *testing.T) {
	t.Parallel()
	for name, in := range map[string]string{
		"application profile": arnApp,
		"provisioned model":   arnProv,
		"malformed":           "arn:aws:bedrock:us-east-1:foundation-model",
		"not bedrock":         "arn:aws:s3:::bucket/key",
		"unknown partition":   "arn:aws-xx:bedrock:us-east-1::foundation-model/m",
		"custom model":        "arn:aws:bedrock:us-east-1:123456789012:custom-model/cm1",
		"empty resource":      "arn:aws:bedrock:us-east-1::foundation-model/",
		"imported model":      "arn:aws:bedrock:us-east-1:123456789012:imported-model/im1",
	} {
		got := SlugCandidates(in)
		assert.Equal(t, []string{in}, got, name+": only the literal, never a guessed model")
	}
}

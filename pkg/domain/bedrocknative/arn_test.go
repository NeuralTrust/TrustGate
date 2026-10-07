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

package bedrocknative

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseBedrockARN(t *testing.T) {
	t.Parallel()
	a, ok := ParseBedrockARN("arn:aws:bedrock:us-east-1:123456789012:application-inference-profile/abc123xyz")
	assert.True(t, ok)
	assert.Equal(t, "us-east-1", a.Region)
	assert.Equal(t, "123456789012", a.Account)
	assert.Equal(t, "application-inference-profile", a.Kind)
	assert.Equal(t, "abc123xyz", a.Resource)
	assert.True(t, a.Opaque())
	_, hasModel := a.ModelID()
	assert.False(t, hasModel)

	_, ok = ParseOpaqueBedrockARN("arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-sonnet-4-5-20250929-v1:0")
	assert.False(t, ok)
	_, ok = ParseOpaqueBedrockARN("arn:aws:bedrock:us-east-1:123456789012:provisioned-model/pt1234")
	assert.True(t, ok)

	id, ok := ModelIDFromModelARN("arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-sonnet-4-5-20250929-v1:0")
	assert.True(t, ok)
	assert.Equal(t, "anthropic.claude-sonnet-4-5-20250929-v1:0", id)
	_, ok = ModelIDFromModelARN("nonsense")
	assert.False(t, ok)
}

// The ARN parser is what decides whether a lookup happens at all, so an ARN whose
// scope is not an AWS partition, region and account is not an ARN to it.
func TestParseBedrockARN_RefusesAScopeThatIsNotAWS(t *testing.T) {
	t.Parallel()
	for _, arn := range []string{
		"arn:aws:bedrock:evil.example/:123456789012:application-inference-profile/abc",
		"arn:aws:bedrock:attacker.example.com:123456789012:application-inference-profile/abc",
		"arn:aws:bedrock::123456789012:application-inference-profile/abc",
		"arn:aws:bedrock:us-east-1:12345:application-inference-profile/abc",
		"arn:aws:bedrock:cn-north-1:123456789012:application-inference-profile/abc",
		"arn:aws-cn:bedrock:us-east-1:123456789012:application-inference-profile/abc",
	} {
		_, ok := ParseBedrockARN(arn)
		assert.False(t, ok, arn)
		_, ok = ParseOpaqueBedrockARN(arn)
		assert.False(t, ok, arn)
	}
	_, ok := ParseBedrockARN("arn:aws:bedrock:us-east-1:123456789012:application-inference-profile/abc")
	assert.True(t, ok)
	_, ok = ParseBedrockARN("arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-v2")
	assert.True(t, ok, "a foundation model's ARN has no account")
}

func TestSplitBedrockARN_JudgesNothing(t *testing.T) {
	t.Parallel()
	a, ok := SplitBedrockARN("arn:aws:s3:evil:999:thing/x")
	assert.True(t, ok)
	assert.Equal(t, "evil", a.Region)
	assert.Equal(t, "thing", a.Kind)
	assert.Equal(t, "x", a.Resource)
	_, ok = SplitBedrockARN("not-an-arn")
	assert.False(t, ok)
}

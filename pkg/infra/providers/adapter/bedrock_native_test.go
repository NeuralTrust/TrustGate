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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testProfileARN = "arn:aws:bedrock:us-east-1:123456789012:inference-profile/us.anthropic.claude-3-5-sonnet-20241022-v2:0"
	testFoundARN   = "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-haiku-20240307-v1:0"
)

func TestParseBedrockNativePath(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		rest    string
		wantOp  BedrockNativeOp
		wantRaw string
		wantID  string
	}{
		{"converse plain id", "/model/anthropic.claude-3-haiku-20240307-v1:0/converse", BedrockOpConverse,
			"anthropic.claude-3-haiku-20240307-v1:0", "anthropic.claude-3-haiku-20240307-v1:0"},
		{"converse-stream", "/model/amazon.nova-lite-v1:0/converse-stream", BedrockOpConverseStream,
			"amazon.nova-lite-v1:0", "amazon.nova-lite-v1:0"},
		{"invoke", "/model/amazon.titan-text-express-v1/invoke", BedrockOpInvoke,
			"amazon.titan-text-express-v1", "amazon.titan-text-express-v1"},
		{"invoke stream", "/model/meta.llama3-8b-instruct-v1:0/invoke-with-response-stream", BedrockOpInvokeStream,
			"meta.llama3-8b-instruct-v1:0", "meta.llama3-8b-instruct-v1:0"},
		{"inference profile id", "/model/us.anthropic.claude-3-5-sonnet-20241022-v2:0/converse", BedrockOpConverse,
			"us.anthropic.claude-3-5-sonnet-20241022-v2:0", "us.anthropic.claude-3-5-sonnet-20241022-v2:0"},
		{"encoded profile ARN", "/model/arn%3Aaws%3Abedrock%3Aus-east-1%3A123456789012%3Ainference-profile%2Fus.anthropic.claude-3-5-sonnet-20241022-v2%3A0/converse",
			BedrockOpConverse,
			"arn%3Aaws%3Abedrock%3Aus-east-1%3A123456789012%3Ainference-profile%2Fus.anthropic.claude-3-5-sonnet-20241022-v2%3A0",
			testProfileARN},
		{"raw profile ARN", "/model/" + testProfileARN + "/converse-stream", BedrockOpConverseStream, testProfileARN, testProfileARN},
		{"encoded foundation model ARN", "/model/arn%3Aaws%3Abedrock%3Aus-east-1%3A%3Afoundation-model%2Fanthropic.claude-3-haiku-20240307-v1%3A0/invoke",
			BedrockOpInvoke,
			"arn%3Aaws%3Abedrock%3Aus-east-1%3A%3Afoundation-model%2Fanthropic.claude-3-haiku-20240307-v1%3A0",
			testFoundARN},
		{"encoded colon in plain id", "/model/amazon.nova-lite-v1%3A0/converse", BedrockOpConverse,
			"amazon.nova-lite-v1%3A0", "amazon.nova-lite-v1:0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseBedrockNativePath(tc.rest)
			require.NoError(t, err)
			assert.Equal(t, tc.wantOp, got.Op)
			assert.Equal(t, tc.wantRaw, got.RawModelID)
			assert.Equal(t, tc.wantID, got.ModelID)
		})
	}
}

func TestParseBedrockNativePath_NotARoute(t *testing.T) {
	t.Parallel()
	for _, rest := range []string{
		"/v1/chat/completions",
		"/model",
		"/model/",
		"/model/amazon.nova-lite-v1:0",
		"/model/amazon.nova-lite-v1:0/count-tokens",
		"/model/amazon.nova-lite-v1:0/converse/extra",
		"/models/amazon.nova-lite-v1:0/converse",
	} {
		_, err := ParseBedrockNativePath(rest)
		assert.ErrorIs(t, err, ErrNotBedrockNativePath, rest)
	}
}

func TestParseBedrockNativePath_RejectsUnsafeModelIDs(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"empty id":                     "/model//converse",
		"dot dot segment":              "/model/arn:aws:bedrock:r:1:x/../converse",
		"encoded dot dot":              "/model/%2e%2e/converse",
		"encoded dot dot in arn":       "/model/arn:aws:x%2F..%2Fy/converse",
		"single dot":                   "/model/./converse",
		"slash outside an ARN":         "/model/anthropic/claude/converse",
		"encoded slash outside an ARN": "/model/anthropic%2Fclaude/converse",
		"encoded question mark":        "/model/model%3Fx=1/converse",
		"encoded fragment":             "/model/model%23x/converse",
		"encoded percent":              "/model/model%25/converse",
		"encoded space":                "/model/model%20x/converse",
		"encoded newline":              "/model/model%0Ax/converse",
		"plus sign":                    "/model/model+x/converse",
		"bad percent encoding":         "/model/model%zz/converse",
		"non ascii":                    "/model/mod%C3%A9l/converse",
		"too long":                     "/model/" + repeat('a', bedrockModelIDMaxBytes+1) + "/converse",
		"backslash":                    "/model/a%5Cb/converse",
		"encoded null":                 "/model/a%00b/converse",
		"semicolon":                    "/model/a;b/converse",
		"at sign":                      "/model/a@b/converse",
		"ARN with dot segment":         "/model/arn:aws:bedrock:r:1:inference-profile/./x/converse",
	}
	for name, rest := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseBedrockNativePath(rest)
			require.Error(t, err)
			assert.True(t, errors.Is(err, ErrInvalidBedrockModelID), "got %v", err)
		})
	}
}

func repeat(b byte, n int) string {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return string(out)
}

func TestBedrockNativeRoute_UpstreamPath(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		route    BedrockNativeRoute
		wantPath string
		wantRaw  string
	}{
		{
			name:     "plain id is forwarded as received",
			route:    BedrockNativeRoute{Op: BedrockOpConverse, RawModelID: "amazon.nova-lite-v1:0", ModelID: "amazon.nova-lite-v1:0"},
			wantPath: "/model/amazon.nova-lite-v1:0/converse",
			wantRaw:  "/model/amazon.nova-lite-v1:0/converse",
		},
		{
			name:     "encoded colon stays encoded",
			route:    BedrockNativeRoute{Op: BedrockOpInvoke, RawModelID: "amazon.nova-lite-v1%3A0", ModelID: "amazon.nova-lite-v1:0"},
			wantPath: "/model/amazon.nova-lite-v1:0/invoke",
			wantRaw:  "/model/amazon.nova-lite-v1%3A0/invoke",
		},
		{
			name: "encoded ARN stays encoded",
			route: BedrockNativeRoute{
				Op:         BedrockOpConverseStream,
				RawModelID: "arn%3Aaws%3Abedrock%3Aus-east-1%3A1%3Ainference-profile%2Fx.y%3A0",
				ModelID:    "arn:aws:bedrock:us-east-1:1:inference-profile/x.y:0",
			},
			wantPath: "/model/arn:aws:bedrock:us-east-1:1:inference-profile/x.y:0/converse-stream",
			wantRaw:  "/model/arn%3Aaws%3Abedrock%3Aus-east-1%3A1%3Ainference-profile%2Fx.y%3A0/converse-stream",
		},
		{
			name: "raw ARN slash is escaped, colons are kept",
			route: BedrockNativeRoute{
				Op:         BedrockOpInvokeStream,
				RawModelID: "arn:aws:bedrock:us-east-1:1:inference-profile/x.y:0",
				ModelID:    "arn:aws:bedrock:us-east-1:1:inference-profile/x.y:0",
			},
			wantPath: "/model/arn:aws:bedrock:us-east-1:1:inference-profile/x.y:0/invoke-with-response-stream",
			wantRaw:  "/model/arn:aws:bedrock:us-east-1:1:inference-profile%2Fx.y:0/invoke-with-response-stream",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path, raw := tc.route.UpstreamPath()
			assert.Equal(t, tc.wantPath, path)
			assert.Equal(t, tc.wantRaw, raw)
		})
	}
}

func TestBedrockNativeOp_Classification(t *testing.T) {
	t.Parallel()
	assert.True(t, BedrockOpConverseStream.IsStream())
	assert.True(t, BedrockOpInvokeStream.IsStream())
	assert.False(t, BedrockOpConverse.IsStream())
	assert.False(t, BedrockOpInvoke.IsStream())
	assert.True(t, BedrockOpConverse.IsConverse())
	assert.True(t, BedrockOpConverseStream.IsConverse())
	assert.False(t, BedrockOpInvoke.IsConverse())
	assert.False(t, BedrockOpInvokeStream.IsConverse())
}

// An ARN in the path is the caller's, and its region is written into hosts by the
// code that resolves it: the gateway refuses one whose scope is not an AWS
// partition, region and account.
func TestValidateBedrockModelID_ARNScopeIsChecked(t *testing.T) {
	t.Parallel()
	for name, id := range map[string]string{
		"region with a slash and a dot (the reviewer's payload)": "arn:aws:bedrock:evil.example/:123456789012:application-inference-profile/abc",
		"region that is a host":                                  "arn:aws:bedrock:attacker.example.com:123456789012:application-inference-profile/abc",
		"empty region":                                           "arn:aws:bedrock::123456789012:application-inference-profile/abc",
		"uppercase region":                                       "arn:aws:bedrock:US-EAST-1:123456789012:application-inference-profile/abc",
		"account that is not 12 digits":                          "arn:aws:bedrock:us-east-1:12345:application-inference-profile/abc",
		"account with letters":                                   "arn:aws:bedrock:us-east-1:12345678901a:application-inference-profile/abc",
		"unknown partition":                                      "arn:evil:bedrock:us-east-1:123456789012:application-inference-profile/abc",
		"china region in the aws partition":                      "arn:aws:bedrock:cn-north-1:123456789012:application-inference-profile/abc",
		"commercial region in the china partition":               "arn:aws-cn:bedrock:us-east-1:123456789012:application-inference-profile/abc",
		"too few sections":                                       "arn:aws:bedrock:us-east-1",
	} {
		err := ValidateBedrockModelID(id)
		assert.ErrorIs(t, err, ErrInvalidBedrockModelID, name)
	}
	for name, id := range map[string]string{
		"application profile":  "arn:aws:bedrock:us-east-1:123456789012:application-inference-profile/abc123xyz",
		"foundation model":     "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-v2",
		"gov cloud":            "arn:aws-us-gov:bedrock:us-gov-west-1:123456789012:inference-profile/us-gov.anthropic.claude-v2",
		"china":                "arn:aws-cn:bedrock:cn-north-1:123456789012:provisioned-model/pt1",
		"a plain model id":     "amazon.nova-lite-v1:0",
		"an inference profile": "us.anthropic.claude-3-5-sonnet-20241022-v2:0",
	} {
		assert.NoError(t, ValidateBedrockModelID(id), name)
	}
}

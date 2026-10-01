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

package bedrock

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	bedrockTypes "github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
	smithy "github.com/aws/smithy-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCacheCapabilityFor(t *testing.T) {
	t.Parallel()

	tests := []struct {
		model string
		want  cacheCapability
	}{
		{"anthropic.claude-sonnet-4-6", claudeCache1h},
		{"global.anthropic.claude-sonnet-4-6", claudeCache1h},
		{"us.anthropic.claude-opus-4-5-20251101-v1:0", claudeCache1h},
		{"eu.anthropic.claude-haiku-4-5-20251001-v1:0", claudeCache1h},
		{"apac.anthropic.claude-sonnet-4-5-20250929-v1:0", claudeCache1h},
		{"jp.anthropic.claude-opus-5-5", claudeCache1h},
		{"au.anthropic.claude-fable-5-1", claudeCache1h},
		{"ca.anthropic.claude-mythos-5", claudeCache1h},
		{"us-gov.anthropic.claude-3-7-sonnet-20250219-v1:0", claudeCache5m},
		{"anthropic.claude-3-7-sonnet-20250219-v1:0", claudeCache5m},
		{"anthropic.claude-3-5-sonnet-20241022-v2:0", claudeCache5m},
		{"US.Anthropic.Claude-Opus-4-8", claudeCache1h},
		{"amazon.nova-lite-v1:0", novaCache},
		{"us.amazon.nova-pro-v1:0", novaCache},
		{"amazon.nova-premier-v1:0", novaCache},
		{"global.amazon.nova-2-lite-v1:0", novaCache},
		{"anthropic.claude-3-5-sonnet-20240620-v1:0", cacheCapability{}},
		{"anthropic.claude-sonnet-4-20250514-v1:0", cacheCapability{}},
		{"anthropic.claude-opus-4-1-20250805-v1:0", cacheCapability{}},
		{"anthropic.claude-opus-4-50", cacheCapability{}},
		{"mistral.mistral-7b-instruct-v0:2", cacheCapability{}},
		{"meta.llama3-3-70b-instruct-v1:0", cacheCapability{}},
		{"amazon.titan-text-express-v1", cacheCapability{}},
		{"arn:aws:bedrock:eu-west-1:065069198444:application-inference-profile/hfeskwe5y945", cacheCapability{}},
		{"arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-sonnet-4-6", claudeCache1h},
		{"arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-7-sonnet-20250219-v1:0", claudeCache5m},
		{"arn:aws:bedrock:us-east-1:123456789012:inference-profile/us.anthropic.claude-sonnet-4-6", claudeCache1h},
		{"arn:aws-us-gov:bedrock:us-gov-west-1:123456789012:inference-profile/us-gov.anthropic.claude-3-7-sonnet-20250219-v1:0", claudeCache5m},
		{"arn:aws:bedrock:us-east-1:123456789012:inference-profile/global.amazon.nova-2-lite-v1:0", novaCache},
		{"arn:aws:bedrock:us-east-1::foundation-model/meta.llama3-3-70b-instruct-v1:0", cacheCapability{}},
		{"arn:aws:bedrock:us-east-1:123456789012:provisioned-model/abc123", cacheCapability{}},
		{"arn:aws:bedrock:us-east-1:123456789012:custom-model/anthropic.claude-sonnet-4-6/abc123", cacheCapability{}},
		{"arn:aws:bedrock:us-east-1::foundation-model/", cacheCapability{}},
		{"arn:aws:bedrock:us-east-1", cacheCapability{}},
		{"", cacheCapability{}},
	}
	for _, tt := range tests {
		t.Run(tt.model, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, cacheCapabilityFor(tt.model))
		})
	}
}

const cachedBody = `{
	"system":[{"text":"rules"},{"cachePoint":{"type":"default","ttl":"1h"}}],
	"messages":[{"role":"user","content":[{"text":"doc"},{"cachePoint":{"type":"default","ttl":"1h"}},{"text":"question"},{"cachePoint":{"type":"default"}}]}],
	"toolConfig":{"tools":[{"toolSpec":{"name":"f","inputSchema":{"json":{"type":"object"}}}},{"cachePoint":{"type":"default","ttl":"1h"}}]}
}`

type sentCachePoints struct {
	system, messages, tools []bedrockTypes.CachePointBlock
}

func (s sentCachePoints) total() int {
	return len(s.system) + len(s.messages) + len(s.tools)
}

func cachePointsOf(system []bedrockTypes.SystemContentBlock, messages []bedrockTypes.Message, tools *bedrockTypes.ToolConfiguration) sentCachePoints {
	var out sentCachePoints
	for _, b := range system {
		if cp, ok := b.(*bedrockTypes.SystemContentBlockMemberCachePoint); ok {
			out.system = append(out.system, cp.Value)
		}
	}
	for _, m := range messages {
		for _, b := range m.Content {
			if cp, ok := b.(*bedrockTypes.ContentBlockMemberCachePoint); ok {
				out.messages = append(out.messages, cp.Value)
			}
		}
	}
	if tools != nil {
		for _, b := range tools.Tools {
			if cp, ok := b.(*bedrockTypes.ToolMemberCachePoint); ok {
				out.tools = append(out.tools, cp.Value)
			}
		}
	}
	return out
}

func sentPoints(in *bedrockruntime.ConverseInput) sentCachePoints {
	return cachePointsOf(in.System, in.Messages, in.ToolConfig)
}

func decodeCached(t *testing.T) *converseParams {
	t.Helper()
	params, err := decodeConverseBody([]byte(cachedBody))
	require.NoError(t, err)
	return params
}

func TestApplyCacheCapability(t *testing.T) {
	t.Parallel()

	oneHour := bedrockTypes.CachePointBlock{Type: bedrockTypes.CachePointTypeDefault, Ttl: bedrockTypes.CacheTTLOneHour}
	fiveMin := bedrockTypes.CachePointBlock{Type: bedrockTypes.CachePointTypeDefault}

	t.Run("1h model keeps everything", func(t *testing.T) {
		t.Parallel()
		params := decodeCached(t)
		params.applyCacheCapability(cacheCapabilityFor("global.anthropic.claude-sonnet-4-6"))
		got := sentPoints(params.input("m"))
		assert.Equal(t, []bedrockTypes.CachePointBlock{oneHour}, got.system)
		assert.Equal(t, []bedrockTypes.CachePointBlock{oneHour, fiveMin}, got.messages)
		assert.Equal(t, []bedrockTypes.CachePointBlock{oneHour}, got.tools)
	})
	t.Run("1h cleared on Claude 3.7 Sonnet", func(t *testing.T) {
		t.Parallel()
		params := decodeCached(t)
		params.applyCacheCapability(cacheCapabilityFor("us.anthropic.claude-3-7-sonnet-20250219-v1:0"))
		got := sentPoints(params.input("m"))
		assert.Equal(t, []bedrockTypes.CachePointBlock{fiveMin}, got.system)
		assert.Equal(t, []bedrockTypes.CachePointBlock{fiveMin, fiveMin}, got.messages)
		assert.Equal(t, []bedrockTypes.CachePointBlock{fiveMin}, got.tools)
	})
	t.Run("Nova drops the tools cachePoint and the 1h ttl", func(t *testing.T) {
		t.Parallel()
		params := decodeCached(t)
		params.applyCacheCapability(cacheCapabilityFor("us.amazon.nova-lite-v1:0"))
		in := params.input("m")
		got := sentPoints(in)
		assert.Equal(t, []bedrockTypes.CachePointBlock{fiveMin}, got.system)
		assert.Equal(t, []bedrockTypes.CachePointBlock{fiveMin, fiveMin}, got.messages)
		assert.Empty(t, got.tools)
		require.Len(t, in.ToolConfig.Tools, 1)
		assert.IsType(t, &bedrockTypes.ToolMemberToolSpec{}, in.ToolConfig.Tools[0])
	})
	t.Run("Mistral 7B gets no cachePoint", func(t *testing.T) {
		t.Parallel()
		params := decodeCached(t)
		params.applyCacheCapability(cacheCapabilityFor("mistral.mistral-7b-instruct-v0:2"))
		in := params.input("m")
		assert.Zero(t, sentPoints(in).total())
		assert.Len(t, in.System, 1)
		assert.Len(t, in.Messages[0].Content, 2)
		assert.Len(t, in.ToolConfig.Tools, 1)
	})
	t.Run("ARN gets no cachePoint", func(t *testing.T) {
		t.Parallel()
		params := decodeCached(t)
		params.applyCacheCapability(cacheCapabilityFor("arn:aws:bedrock:eu-west-1:065069198444:application-inference-profile/hfeskwe5y945"))
		assert.Zero(t, sentPoints(params.input("m")).total())
	})
}

func TestStripCachePoints_LeavesEarlierInputsAlone(t *testing.T) {
	t.Parallel()

	params := decodeCached(t)
	before := params.input("m")
	require.True(t, params.stripCachePoints())
	assert.Equal(t, 4, sentPoints(before).total())
	assert.Zero(t, sentPoints(params.input("m")).total())
	assert.False(t, params.stripCachePoints(), "nothing left to strip")
}

func cachePointErr() error {
	return &smithy.GenericAPIError{Code: "ValidationException", Message: "This model doesn't support the cachePoint field. Remove cachePoint from your request and try again."}
}

const claudeCachedBody = `{"model":"us.anthropic.claude-sonnet-4-6",
	"system":[{"text":"rules"},{"cachePoint":{"type":"default"}}],
	"messages":[{"role":"user","content":[{"text":"hi"}]}]}`

func TestCompletions_RetriesWithoutCachePointOnValidationException(t *testing.T) {
	t.Parallel()

	var inputs []*bedrockruntime.ConverseInput
	c := &client{
		converse: func(_ context.Context, input *bedrockruntime.ConverseInput) (*bedrockruntime.ConverseOutput, error) {
			inputs = append(inputs, input)
			if sentPoints(input).total() > 0 {
				return nil, cachePointErr()
			}
			return helloOutput(), nil
		},
	}

	out, err := c.Completions(context.Background(), &providers.Config{}, []byte(claudeCachedBody))
	require.NoError(t, err)
	assert.Contains(t, string(out), `"Blue"`)
	require.Len(t, inputs, 2)
	assert.Equal(t, 1, sentPoints(inputs[0]).total())
	assert.Zero(t, sentPoints(inputs[1]).total())
	require.Len(t, inputs[1].System, 1)

	inputs = nil
	_, err = c.Completions(context.Background(), &providers.Config{}, []byte(claudeCachedBody))
	require.NoError(t, err)
	require.Len(t, inputs, 2, "nothing is remembered: the next request tries its cachePoints again")
	assert.Equal(t, 1, sentPoints(inputs[0]).total())
}

func TestCompletions_NoCachePointRetryOnOtherErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
	}{
		{"throttling", &smithy.GenericAPIError{Code: "ThrottlingException", Message: "Too many requests, cache later."}},
		{"unrelated validation", &smithy.GenericAPIError{Code: "ValidationException", Message: "The provided model identifier is invalid."}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var inputs []*bedrockruntime.ConverseInput
			c := &client{
				converse: func(_ context.Context, input *bedrockruntime.ConverseInput) (*bedrockruntime.ConverseOutput, error) {
					inputs = append(inputs, input)
					return nil, tt.err
				},
			}
			_, err := c.Completions(context.Background(), &providers.Config{}, []byte(claudeCachedBody))
			require.Error(t, err)
			require.Len(t, inputs, 1)
			assert.Equal(t, 1, sentPoints(inputs[0]).total())
		})
	}
}

func TestCompletions_CachePointRetryHappensOnce(t *testing.T) {
	t.Parallel()

	calls := 0
	c := &client{
		converse: func(_ context.Context, input *bedrockruntime.ConverseInput) (*bedrockruntime.ConverseOutput, error) {
			calls++
			if sentPoints(input).total() > 0 {
				return nil, cachePointErr()
			}
			return nil, &smithy.GenericAPIError{Code: "ValidationException", Message: "messages: text field is blank"}
		},
	}

	_, err := c.Completions(context.Background(), &providers.Config{}, []byte(claudeCachedBody))
	require.Error(t, err)
	assert.Equal(t, 2, calls, "one retry without cachePoint")
}

func TestCompletions_CachePointAndSystemFallbacksInEitherOrder(t *testing.T) {
	t.Parallel()

	const model = "anthropic.claude-sonnet-4-6"
	body := []byte(`{"model":"` + model + `",
		"system":[{"text":"rules"},{"cachePoint":{"type":"default"}}],
		"messages":[{"role":"user","content":[{"text":"hi"}]}]}`)

	tests := []struct {
		name   string
		reject func(*bedrockruntime.ConverseInput) error
	}{
		{"cachePoint checked first", func(in *bedrockruntime.ConverseInput) error {
			if sentPoints(in).total() > 0 {
				return cachePointErr()
			}
			if len(in.System) > 0 {
				return systemUnsupportedErr()
			}
			return nil
		}},
		{"system checked first", func(in *bedrockruntime.ConverseInput) error {
			if len(in.System) > 0 {
				return systemUnsupportedErr()
			}
			if sentPoints(in).total() > 0 {
				return cachePointErr()
			}
			return nil
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var inputs []*bedrockruntime.ConverseInput
			c := &client{
				converse: func(_ context.Context, input *bedrockruntime.ConverseInput) (*bedrockruntime.ConverseOutput, error) {
					inputs = append(inputs, input)
					if err := tt.reject(input); err != nil {
						return nil, err
					}
					return helloOutput(), nil
				},
			}

			_, err := c.Completions(context.Background(), &providers.Config{}, body)
			require.NoError(t, err)
			last := inputs[len(inputs)-1]
			assert.Empty(t, last.System)
			assert.Zero(t, sentPoints(last).total())
			assert.True(t, c.systemFold.known(model))

			inputs = nil
			_, err = c.Completions(context.Background(), &providers.Config{}, body)
			require.NoError(t, err)
			require.Len(t, inputs, 2, "only the system fold is remembered")
			assert.Empty(t, inputs[0].System)
			assert.Equal(t, 1, sentPoints(inputs[0]).total(), "the folded system keeps its cachePoint")
			assert.Zero(t, sentPoints(inputs[1]).total())
		})
	}
}

func TestCompletionsStream_RetriesWithoutCachePoint(t *testing.T) {
	t.Parallel()

	var inputs []*bedrockruntime.ConverseStreamInput
	c := &client{
		converseStream: func(_ context.Context, input *bedrockruntime.ConverseStreamInput) (*bedrockruntime.ConverseStreamOutput, error) {
			inputs = append(inputs, input)
			if cachePointsOf(input.System, input.Messages, input.ToolConfig).total() > 0 {
				return nil, cachePointErr()
			}
			return &bedrockruntime.ConverseStreamOutput{}, nil
		},
	}

	_, err := c.CompletionsStream(context.Background(), &providers.Config{}, []byte(claudeCachedBody))
	require.NoError(t, err)
	require.Len(t, inputs, 2)
	assert.Equal(t, 1, cachePointsOf(inputs[0].System, inputs[0].Messages, inputs[0].ToolConfig).total())
	assert.Zero(t, cachePointsOf(inputs[1].System, inputs[1].Messages, inputs[1].ToolConfig).total())

	inputs = nil
	_, err = c.CompletionsStream(context.Background(), &providers.Config{}, []byte(claudeCachedBody))
	require.NoError(t, err)
	require.Len(t, inputs, 2)
	assert.Equal(t, 1, cachePointsOf(inputs[0].System, inputs[0].Messages, inputs[0].ToolConfig).total())
}

func TestCompletionsStream_GatesCachePointByModel(t *testing.T) {
	t.Parallel()

	var sent *bedrockruntime.ConverseStreamInput
	c := &client{
		converseStream: func(_ context.Context, input *bedrockruntime.ConverseStreamInput) (*bedrockruntime.ConverseStreamOutput, error) {
			sent = input
			return &bedrockruntime.ConverseStreamOutput{}, nil
		},
	}
	body := []byte(`{"model":"mistral.mistral-large-2407-v1:0","system":[{"text":"rules"},{"cachePoint":{"type":"default"}}],"messages":[{"role":"user","content":[{"text":"hi"}]}]}`)

	_, err := c.CompletionsStream(context.Background(), &providers.Config{}, body)
	require.NoError(t, err)
	require.NotNil(t, sent)
	assert.Zero(t, cachePointsOf(sent.System, sent.Messages, sent.ToolConfig).total())
	assert.Len(t, sent.System, 1)
}

func TestCachePointRejected(t *testing.T) {
	t.Parallel()

	tests := []struct {
		code, message string
		want          bool
	}{
		{"ValidationException", "A maximum of 4 blocks with cache_control may be provided. Found 5.", true},
		{"ValidationException", "The model returned the following errors: Malformed input request: extraneous key [cachePoint] is not permitted, please reformat your input and try again.", true},
		{"ValidationException", "This model doesn't support the cachePoint field. Remove cachePoint from your request and try again.", true},
		{"ValidationException", "cache_control with ttl='1h' must not come after ttl='5m'", true},
		{"ValidationException", "A cache point must follow a content block.", true},
		{"ValidationException", "Too many cache checkpoints in the request.", true},
		{"ValidationException", "The ttl 1h is not supported for prompt caching on this model.", true},
		{"ValidationException", "The provided model identifier is invalid.", false},
		{"ValidationException", "cache unavailable", false},
		{"ValidationException", "Invalid ttl for guardrail trace.", false},
		{"ValidationException", "messages: text field is blank", false},
		{"ThrottlingException", "Too many requests with cachePoint, please wait.", false},
		{"ServiceUnavailableException", "cache_control backend unavailable", false},
	}
	for _, tt := range tests {
		t.Run(tt.message, func(t *testing.T) {
			t.Parallel()
			err := &smithy.GenericAPIError{Code: tt.code, Message: tt.message}
			assert.Equal(t, tt.want, cachePointRejected(err))
		})
	}
	assert.False(t, cachePointRejected(errors.New("cachePoint")), "not an API error")
}

func TestCompletions_MalformedCacheRequestDoesNotDisableCachingForTheModel(t *testing.T) {
	t.Parallel()

	const model = "us.anthropic.claude-sonnet-4-5-20250929-v1:0"
	valid := `{"model":"` + model + `","system":[{"text":"rules"},{"cachePoint":{"type":"default"}}],"messages":[{"role":"user","content":[{"text":"hi"}]}]}`
	tests := []struct {
		name   string
		body   string
		reject func(sentCachePoints) error
	}{
		{
			name: "more than four cachePoints",
			body: `{"model":"` + model + `","system":[{"text":"a"},{"cachePoint":{"type":"default"}},{"text":"b"},{"cachePoint":{"type":"default"}},{"text":"c"},{"cachePoint":{"type":"default"}}],"messages":[{"role":"user","content":[{"text":"d"},{"cachePoint":{"type":"default"}},{"text":"e"},{"cachePoint":{"type":"default"}}]}]}`,
			reject: func(sent sentCachePoints) error {
				if sent.total() > 4 {
					return &smithy.GenericAPIError{Code: "ValidationException", Message: "A maximum of 4 blocks with cache_control may be provided. Found 5."}
				}
				return nil
			},
		},
		{
			name: "1h ttl after 5m",
			body: `{"model":"` + model + `","system":[{"text":"a"},{"cachePoint":{"type":"default"}}],"messages":[{"role":"user","content":[{"text":"d"},{"cachePoint":{"type":"default","ttl":"1h"}}]}]}`,
			reject: func(sent sentCachePoints) error {
				if len(sent.system) > 0 && len(sent.messages) > 0 && sent.system[0].Ttl == "" && sent.messages[0].Ttl == bedrockTypes.CacheTTLOneHour {
					return &smithy.GenericAPIError{Code: "ValidationException", Message: "cache_control with ttl='1h' must not come after ttl='5m'"}
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		for _, stream := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s stream=%v", tt.name, stream), func(t *testing.T) {
				t.Parallel()
				var sent []sentCachePoints
				record := func(p sentCachePoints) error {
					sent = append(sent, p)
					return tt.reject(p)
				}
				c := &client{
					converse: func(_ context.Context, in *bedrockruntime.ConverseInput) (*bedrockruntime.ConverseOutput, error) {
						if err := record(sentPoints(in)); err != nil {
							return nil, err
						}
						return helloOutput(), nil
					},
					converseStream: func(_ context.Context, in *bedrockruntime.ConverseStreamInput) (*bedrockruntime.ConverseStreamOutput, error) {
						if err := record(cachePointsOf(in.System, in.Messages, in.ToolConfig)); err != nil {
							return nil, err
						}
						return &bedrockruntime.ConverseStreamOutput{}, nil
					},
				}
				send := func(body string) error {
					if stream {
						_, err := c.CompletionsStream(context.Background(), &providers.Config{}, []byte(body))
						return err
					}
					_, err := c.Completions(context.Background(), &providers.Config{}, []byte(body))
					return err
				}

				require.NoError(t, send(tt.body))
				require.Len(t, sent, 2, "the malformed request is retried once without cachePoints")
				assert.Zero(t, sent[1].total())

				sent = nil
				require.NoError(t, send(valid))
				require.Len(t, sent, 1)
				assert.Equal(t, 1, sent[0].total(), "the next valid request keeps its cachePoint")
			})
		}
	}
}

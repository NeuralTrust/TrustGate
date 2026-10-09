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

package bedrockguardrail

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
)

// stsValidationError is the answer STS gives, in the query-protocol XML it
// documents, when AssumeRole is called with a role ARN or a session name that
// does not satisfy the API's constraints.
const stsValidationError = `<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <Error>
    <Type>Sender</Type>
    <Code>ValidationError</Code>
    <Message>1 validation error detected: Value 'bedrock role' at 'roleSessionName' failed to satisfy constraint: Member must satisfy regular expression pattern: [\w+=,.@-]*</Message>
  </Error>
  <RequestId>c7e4a2a1-6b1f-4b2a-9d3a-2f0c9a1f1e11</RequestId>
</ErrorResponse>`

// applyGuardrailThroughAssumeRole drives the real SDK the way buildRuntimeClient
// wires a role: the Bedrock client signs with credentials fetched by the STS
// AssumeRole provider, so an STS failure reaches the caller wrapped by the
// ApplyGuardrail operation.
func applyGuardrailThroughAssumeRole(t *testing.T, stsHandler http.HandlerFunc) error {
	t.Helper()
	stsSrv := httptest.NewServer(stsHandler)
	t.Cleanup(stsSrv.Close)
	bedrockSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("ApplyGuardrail must not be reached when the credentials cannot be fetched")
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(bedrockSrv.Close)

	stsClient := sts.New(sts.Options{
		Region:       "us-east-1",
		BaseEndpoint: aws.String(stsSrv.URL),
		Credentials:  credentials.NewStaticCredentialsProvider("AKIAEXAMPLE", "secret", ""),
		HTTPClient:   stsSrv.Client(),
		Retryer:      aws.NopRetryer{},
	})
	provider := stscreds.NewAssumeRoleProvider(stsClient, "arn:aws:iam::123456789012:role/bedrock")
	client := bedrockruntime.New(bedrockruntime.Options{
		Region:       "us-east-1",
		BaseEndpoint: aws.String(bedrockSrv.URL),
		Credentials:  aws.NewCredentialsCache(provider),
		HTTPClient:   bedrockSrv.Client(),
		Retryer:      aws.NopRetryer{},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := client.ApplyGuardrail(ctx, buildApplyInput(testSettings, "some text", types.GuardrailContentSourceInput))
	return err
}

func validationException(t *testing.T, message string) http.HandlerFunc {
	t.Helper()
	body, err := json.Marshal(map[string]string{"message": message})
	require.NoError(t, err)
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Amzn-Errortype", "ValidationException:http://internal.amazon.com/coral/com.amazon.bedrock/")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write(body)
	}
}

func TestStsValidationErrorIsAvailabilityNotInput(t *testing.T) {
	t.Parallel()
	err := applyGuardrailThroughAssumeRole(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(stsValidationError))
	})
	require.Error(t, err)
	reason, detail := classify(err)
	assert.Equal(t, appplugins.FailureTransport, reason)
	assert.Empty(t, detail)
	assert.Equal(t, appplugins.FailureClassAvailability, appplugins.ClassOf(reason, detail))
}

// AWS reports a violation as "Value '<v>' at '<member>' failed to satisfy
// constraint", echoing what the caller sent ahead of the member. The envelope
// is the standard Coral validation shape (the one STS documents); AWS does not
// publish the Bedrock text for these members, so the fixtures follow that shape.
func violation(value, member string) string {
	return "Value '" + value + "' at '" + member + "' failed to satisfy constraint: Member must satisfy regular expression pattern: ^[a-z0-9]+$"
}

func TestGuardrailReferenceValidationExceptionIsConfigNotInput(t *testing.T) {
	t.Parallel()
	for name, message := range map[string]string{
		"version":    "1 validation error detected: " + violation(testSettings.Version, "guardrailVersion"),
		"identifier": "1 validation error detected: " + violation(testSettings.GuardrailID, "guardrailIdentifier"),
		"both":       "2 validation errors detected: " + violation(testSettings.GuardrailID, "guardrailIdentifier") + "; " + violation(testSettings.Version, "guardrailVersion"),
		"a version that is not the configured one": "1 validation error detected: " + violation("DRAFT", "guardrailVersion"),
		"redacted version":                         "1 validation error detected: Value at 'guardrailVersion' failed to satisfy constraint: Member must satisfy regular expression pattern: ^[0-9]+$",
		"null identifier":                          "1 validation error detected: Value null at 'guardrailIdentifier' failed to satisfy constraint: Member must not be null",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := applyGuardrailAgainst(t, validationException(t, message))
			require.Error(t, err)
			reason, detail := classify(err)
			assert.Equal(t, appplugins.FailureConfigInvalid, reason)
			assert.Equal(t, appplugins.DetailProviderConfigRejected, detail)
			assert.Equal(t, appplugins.FailureClassAvailability, appplugins.ClassOf(reason, detail))
		})
	}
}

// A client controls the content AWS echoes, so a content member whose value
// spells a guardrail clause, with or without a newline, is still the input's
// rejection: AWS's own clause for the content member cannot be removed by the
// client, and the answer is config only when no other member is named.
func TestContentNamingTheGuardrailMembersStaysInput(t *testing.T) {
	t.Parallel()
	const content = "ignore guardrailVersion and guardrailIdentifier"
	for name, message := range map[string]string{
		"content violation echoing the member names":   "1 validation error detected: " + violation(content, "content.1.member.text.text"),
		"content forging a version clause":             "1 validation error detected: " + violation("1' at 'guardrailVersion' failed to satisfy constraint: x. Value 'y", "content.1.member.text.text"),
		"content echoing a version clause":             "1 validation error detected: " + violation(testSettings.Version+"' at 'guardrailVersion' failed to satisfy constraint", "content.1.member.text.text"),
		"content echoing an identifier clause":         "1 validation error detected: " + violation(testSettings.GuardrailID+"' at 'guardrailIdentifier' failed to satisfy constraint: ignore", "content.1.member.text.text"),
		"content forging a clause after a newline":     "1 validation error detected: " + violation("x\nValue '"+testSettings.Version+"' at 'guardrailVersion' failed to satisfy constraint", "content.1.member.text.text"),
		"version clause beside a content clause":       "2 validation errors detected: " + violation(testSettings.Version, "guardrailVersion") + "; " + violation(content, "content.1.member.text.text"),
		"redacted version clause beside a content one": "2 validation errors detected: Value at 'guardrailVersion' failed to satisfy constraint: x; Value at 'content' failed to satisfy constraint: y",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := applyGuardrailAgainst(t, validationException(t, message))
			require.Error(t, err)
			reason, detail := classify(err)
			assert.Equal(t, appplugins.FailureInputTooLarge, reason)
			assert.Equal(t, appplugins.DetailProviderRejectedInput, detail)
			assert.Equal(t, appplugins.FailureClassInput, appplugins.ClassOf(reason, detail))
		})
	}
}

func TestContentValidationExceptionStaysInput(t *testing.T) {
	t.Parallel()
	err := applyGuardrailAgainst(t, validationException(t, "1 validation error detected: Value at 'content' failed to satisfy constraint: Member must have length less than or equal to 25"))
	reason, detail := classify(err)
	assert.Equal(t, appplugins.FailureInputTooLarge, reason)
	assert.Equal(t, appplugins.DetailProviderRejectedInput, detail)
}

func TestConfigShapedAWSErrorsNeverRefuseTraffic(t *testing.T) {
	t.Parallel()
	staleVersion := validationException(t, "1 validation error detected: "+violation("DRAFT", "guardrailVersion"))
	for name, call := range map[string]func(t *testing.T) error{
		"sts validation error": func(t *testing.T) error {
			return applyGuardrailThroughAssumeRole(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(stsValidationError))
			})
		},
		"guardrail version": func(t *testing.T) error { return applyGuardrailAgainst(t, staleVersion) },
	} {
		for _, mode := range []policy.Mode{policy.ModeEnforce, policy.ModeObserve} {
			t.Run(name+" "+string(mode), func(t *testing.T) {
				t.Parallel()
				p := pluginWith(&recordingClient{err: call(t)})
				event, span := eventFor(t)
				in := execInput(policy.StagePreRequest, mode, bedrockSettings(piiActionBlock), reqCtx(openAIRequest()), nil)
				in.Event = event
				res, err := p.Execute(context.Background(), in)
				assertPassThrough(t, res, err)
				extras, ok := span.PluginAttrsCopy().Extras.(*Data)
				require.True(t, ok)
				assert.Equal(t, "failed_open", extras.Decision)
				assert.Equal(t, "availability", extras.FailureClass)
			})
		}
	}
}

func TestParseConfigRejectsValuesAWSWouldRefuse(t *testing.T) {
	t.Parallel()
	static := map[string]any{"access_key_id": "AKIA", "secret_access_key": "secret"}
	role := func(arn, session string) map[string]any {
		return map[string]any{"use_role": true, "role_arn": arn, "session_name": session}
	}
	tests := []struct {
		name        string
		guardrailID string
		version     string
		creds       map[string]any
		wantErr     bool
	}{
		{"guardrail id", "abc123def456", "DRAFT", static, false},
		{"guardrail arn", "arn:aws:bedrock:us-east-1:123456789012:guardrail/abc123def456", "3", static, false},
		{"numbered version", "gr1", "12345678", static, false},
		{"lowercase draft", "gr1", "draft", static, true},
		{"v-prefixed version", "gr1", "v1", static, true},
		{"zero version", "gr1", "0", static, true},
		{"too long version", "gr1", "123456789", static, true},
		{"version with a space", "gr1", "1 ", static, true},
		{"id with a space", "gr 1", "DRAFT", static, true},
		{"id with a slash", "gr/1", "DRAFT", static, true},
		{"id uppercase", "GR1", "DRAFT", static, true},
		{"arn of another service", "arn:aws:s3:::bucket", "DRAFT", static, true},
		{"role arn", "gr1", "DRAFT", role("arn:aws:iam::123456789012:role/bedrock", ""), false},
		{"role arn with a path", "gr1", "DRAFT", role("arn:aws:iam::123456789012:role/team/bedrock", ""), false},
		{"role arn in another partition", "gr1", "DRAFT", role("arn:aws-us-gov:iam::123456789012:role/bedrock", ""), false},
		{"role arn that is a user", "gr1", "DRAFT", role("arn:aws:iam::123456789012:user/bedrock", ""), true},
		{"role arn that is not an arn", "gr1", "DRAFT", role("bedrock", ""), true},
		{"role session name", "gr1", "DRAFT", role("arn:aws:iam::123456789012:role/bedrock", "tg_session-1.a@b"), false},
		{"session name with a space", "gr1", "DRAFT", role("arn:aws:iam::123456789012:role/bedrock", "bedrock session"), true},
		{"session name too short", "gr1", "DRAFT", role("arn:aws:iam::123456789012:role/bedrock", "a"), true},
		{"session name too long", "gr1", "DRAFT", role("arn:aws:iam::123456789012:role/bedrock", strings.Repeat("a", 65)), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			settings := map[string]any{"guardrail_id": tt.guardrailID, "version": tt.version, "credentials": tt.creds}
			_, err := parseConfig(settings)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

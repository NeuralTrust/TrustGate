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
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
)

// awsErrorEnvelope is one error answer in the wire shape AWS documents for the
// REST-JSON services: the error type in the x-amzn-ErrorType header (Bedrock
// appends the coral namespace after a colon) and a {"message": ...} body. The
// answers are served over HTTP and parsed by the real SDK client, so the test
// reads what the SDK makes of the wire, not a struct built by hand.
type awsErrorEnvelope struct {
	name    string
	status  int
	errType string
	message string
	reason  appplugins.FailureReason
	detail  string
}

var awsApplyGuardrailErrors = []awsErrorEnvelope{
	{"validation", http.StatusBadRequest, "ValidationException", "The input text is not valid.", appplugins.FailureInputTooLarge, appplugins.DetailProviderRejectedInput},
	{"validation with another message", http.StatusBadRequest, "ValidationException", "1 validation error detected", appplugins.FailureInputTooLarge, appplugins.DetailProviderRejectedInput},
	{"conflict", http.StatusConflict, "ConflictException", "conflict", appplugins.FailureInputTooLarge, appplugins.DetailProviderRejectedInput},

	{"access denied", http.StatusForbidden, "AccessDeniedException", "User is not authorized to perform: bedrock:ApplyGuardrail", appplugins.FailureTransport, ""},
	{"unrecognized client", http.StatusForbidden, "UnrecognizedClientException", "The security token included in the request is invalid.", appplugins.FailureTransport, ""},
	{"expired token is a 400", http.StatusBadRequest, "ExpiredTokenException", "The security token included in the request is expired", appplugins.FailureTransport, ""},
	{"invalid signature", http.StatusForbidden, "InvalidSignatureException", "The request signature we calculated does not match the signature you provided.", appplugins.FailureTransport, ""},
	{"throttling", http.StatusTooManyRequests, "ThrottlingException", "Too many requests, please wait before trying again.", appplugins.FailureTransport, ""},
	{"quota exceeded is a 400", http.StatusBadRequest, "ServiceQuotaExceededException", "quota", appplugins.FailureTransport, ""},
	{"guardrail not found", http.StatusNotFound, "ResourceNotFoundException", "The guardrail does not exist.", appplugins.FailureTransport, ""},
	{"request timeout", http.StatusRequestTimeout, "RequestTimeoutException", "timeout", appplugins.FailureTransport, ""},
	{"internal server", http.StatusInternalServerError, "InternalServerException", "internal", appplugins.FailureTransport, ""},
	{"service unavailable", http.StatusServiceUnavailable, "ServiceUnavailableException", "unavailable", appplugins.FailureTransport, ""},
}

func applyGuardrailAgainst(t *testing.T, handler http.HandlerFunc) error {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	client := bedrockruntime.New(bedrockruntime.Options{
		Region:       "us-east-1",
		BaseEndpoint: aws.String(srv.URL),
		Credentials:  credentials.NewStaticCredentialsProvider("AKIAEXAMPLE", "secret", ""),
		HTTPClient:   srv.Client(),
		Retryer:      aws.NopRetryer{},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := client.ApplyGuardrail(ctx, buildApplyInput(Settings{GuardrailID: "gr-1", Version: "1"}, "some text", types.GuardrailContentSourceInput))
	return err
}

func TestClassifyApplyErrReadsTheAWSErrorTypeAndStatus(t *testing.T) {
	t.Parallel()
	for _, tc := range awsApplyGuardrailErrors {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := applyGuardrailAgainst(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("X-Amzn-Errortype", tc.errType+":http://internal.amazon.com/coral/com.amazon.bedrock/")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(`{"message":"` + tc.message + `"}`))
			})
			if err == nil {
				t.Fatal("expected the SDK to return the AWS error")
			}
			reason, detail := classifyApplyErr(err)
			if reason != tc.reason || detail != tc.detail {
				t.Fatalf("classifyApplyErr(%s %d) = %q/%q, want %q/%q", tc.errType, tc.status, reason, detail, tc.reason, tc.detail)
			}
		})
	}
}

// A call that never got an AWS answer is the network's or the caller's, not the
// content's.
func TestClassifyApplyErrTreatsNonAWSFailuresAsTransport(t *testing.T) {
	t.Parallel()
	for name, err := range map[string]error{
		"a plain error":    errors.New("dial tcp: connection refused"),
		"a deadline":       context.DeadlineExceeded,
		"a cancelled call": context.Canceled,
	} {
		if reason, detail := classifyApplyErr(err); reason != appplugins.FailureTransport || detail != "" {
			t.Errorf("%s: classifyApplyErr = %q/%q, want transport", name, reason, detail)
		}
	}
	if reason, _ := classifyApplyErr(applyGuardrailAgainst(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`not json`))
	})); reason != appplugins.FailureTransport {
		t.Errorf("an undecodable 200 = %q, want transport", reason)
	}
}

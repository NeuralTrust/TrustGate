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

package awssm_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/smithy-go"

	"github.com/NeuralTrust/TrustGate/pkg/domain/secretstore"
	"github.com/NeuralTrust/TrustGate/pkg/infra/secretstore/awssm"
)

type fakeAPI struct {
	in  *secretsmanager.GetSecretValueInput
	out *secretsmanager.GetSecretValueOutput
	err error
}

func (f *fakeAPI) GetSecretValue(_ context.Context, in *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	f.in = in
	return f.out, f.err
}

type creds struct{ err error }

func (c creds) Retrieve(context.Context) (aws.Credentials, error) { return aws.Credentials{}, c.err }

func TestFetch(t *testing.T) {
	t.Parallel()
	api := &fakeAPI{out: &secretsmanager.GetSecretValueOutput{SecretString: aws.String(`{"key":"sk-1"}`), VersionId: aws.String("v-1")}}
	b := awssm.NewWithClient(api, creds{})
	s, err := b.Fetch(context.Background(), "prod/llm/openai", "")
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := s.Select("key"); v != "sk-1" || s.Version() != "v-1" {
		t.Fatalf("value %q version %q", v, s.Version())
	}
	if aws.ToString(api.in.SecretId) != "prod/llm/openai" || api.in.VersionId != nil || api.in.VersionStage != nil {
		t.Fatalf("input = %+v", api.in)
	}

	_, _ = b.Fetch(context.Background(), "p", "AWSPREVIOUS")
	if aws.ToString(api.in.VersionStage) != "AWSPREVIOUS" || api.in.VersionId != nil {
		t.Fatalf("staging label input = %+v", api.in)
	}
	id := "0193f0c2-6c1e-7c3a-9b2f-1d2e3f4a5b6c"
	_, _ = b.Fetch(context.Background(), "p", id)
	if aws.ToString(api.in.VersionId) != id || api.in.VersionStage != nil {
		t.Fatalf("version id input = %+v", api.in)
	}

	api.out = &secretsmanager.GetSecretValueOutput{SecretBinary: []byte("sk-bin")}
	if s, err := b.Fetch(context.Background(), "p", ""); err != nil {
		t.Fatal(err)
	} else if v, _ := s.Select(""); v != "sk-bin" {
		t.Fatalf("binary text = %q", v)
	}
	api.out = &secretsmanager.GetSecretValueOutput{SecretBinary: []byte{0xff, 0xfe}}
	if _, err := b.Fetch(context.Background(), "p", ""); !errors.Is(err, secretstore.ErrInvalidPayload) {
		t.Fatalf("binary: %v", err)
	}
}

func TestErrorClasses(t *testing.T) {
	t.Parallel()
	apiErr := func(code string) error {
		return &smithy.GenericAPIError{Code: code, Message: "secret prod/llm/openai sk-live"}
	}
	tests := map[error]error{
		apiErr("ResourceNotFoundException"):                 secretstore.ErrNotFound,
		apiErr("InvalidRequestException"):                   secretstore.ErrNotFound,
		apiErr("AccessDeniedException"):                     secretstore.ErrAccessDenied,
		apiErr("DecryptionFailure"):                         secretstore.ErrAccessDenied,
		apiErr("ExpiredTokenException"):                     secretstore.ErrAuthFailed,
		apiErr("UnrecognizedClientException"):               secretstore.ErrAuthFailed,
		apiErr("ThrottlingException"):                       secretstore.ErrUnavailable,
		apiErr("InternalServiceError"):                      secretstore.ErrUnavailable,
		&v4.SigningError{Err: errors.New("no credentials")}: secretstore.ErrAuthFailed,
		fmt.Errorf("dial tcp: i/o timeout"):                 secretstore.ErrUnavailable,
	}
	for in, want := range tests {
		b := awssm.NewWithClient(&fakeAPI{err: in}, creds{})
		_, err := b.Fetch(context.Background(), "prod/llm/openai", "")
		if !errors.Is(err, want) {
			t.Errorf("%v -> %v, want %v", in, err, want)
		}
		if err != nil && (strings.Contains(err.Error(), "sk-live") || strings.Contains(err.Error(), "prod/llm")) {
			t.Errorf("error %q carries the service message", err)
		}
	}
}

func TestProbe(t *testing.T) {
	t.Parallel()
	if err := awssm.NewWithClient(&fakeAPI{}, creds{}).Probe(context.Background()); err != nil {
		t.Fatal(err)
	}
	err := awssm.NewWithClient(&fakeAPI{}, creds{err: errors.New("no IRSA")}).Probe(context.Background())
	if !errors.Is(err, secretstore.ErrAuthFailed) {
		t.Fatalf("failed credentials: %v", err)
	}
}

func TestNewBuildsWithoutNetwork(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDEXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	b, err := awssm.New(context.Background(), &secretstore.AWSSecretsManagerConfig{
		Region: "eu-west-1", Endpoint: "https://vpce.example", AssumeRoleARN: "arn:aws:iam::123456789012:role/r",
	})
	if err != nil || b == nil {
		t.Fatalf("New: %v", err)
	}
}

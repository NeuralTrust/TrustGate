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

// Package awssm reads AWS Secrets Manager with the SDK's default credential
// chain (IRSA, EKS Pod Identity, an instance profile), optionally assuming a
// role first.
package awssm

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"unicode/utf8"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"

	"github.com/NeuralTrust/TrustGate/pkg/domain/secretstore"
)

const assumeRoleSessionName = "trustgate-secret-store"

// versionIDPattern matches a VersionId, which Secrets Manager issues as a
// UUID. Anything else is read as a staging label such as AWSPREVIOUS.
var versionIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// API is the part of the Secrets Manager client the backend uses.
type API interface {
	GetSecretValue(ctx context.Context, in *secretsmanager.GetSecretValueInput, opts ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

// Backend reads one region of Secrets Manager.
type Backend struct {
	client API
	creds  aws.CredentialsProvider
}

var _ secretstore.Backend = (*Backend)(nil)

// New returns the backend for cfg. Loading the configuration makes no
// network call; credentials are resolved on first use.
func New(ctx context.Context, cfg *secretstore.AWSSecretsManagerConfig) (*Backend, error) {
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(cfg.Region))
	if err != nil {
		return nil, fmt.Errorf("%w: loading the AWS configuration: %v", secretstore.ErrInvalidStore, err)
	}
	if cfg.AssumeRoleARN != "" {
		provider := stscreds.NewAssumeRoleProvider(sts.NewFromConfig(awsCfg), cfg.AssumeRoleARN, func(o *stscreds.AssumeRoleOptions) {
			o.RoleSessionName = assumeRoleSessionName
		})
		awsCfg.Credentials = aws.NewCredentialsCache(provider)
	}
	client := secretsmanager.NewFromConfig(awsCfg, func(o *secretsmanager.Options) {
		if cfg.Endpoint != "" {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
		}
	})
	return NewWithClient(client, awsCfg.Credentials), nil
}

// NewWithClient returns a backend over client, probing with creds.
func NewWithClient(client API, creds aws.CredentialsProvider) *Backend {
	return &Backend{client: client, creds: creds}
}

// Fetch implements secretstore.Backend. The path is the secret's name or
// ARN; a version is a VersionId when it is a UUID and a staging label
// otherwise.
func (b *Backend) Fetch(ctx context.Context, path, version string) (secretstore.Secret, error) {
	in := &secretsmanager.GetSecretValueInput{SecretId: aws.String(path)}
	switch {
	case version == "":
	case versionIDPattern.MatchString(version):
		in.VersionId = aws.String(version)
	default:
		in.VersionStage = aws.String(version)
	}
	out, err := b.client.GetSecretValue(ctx, in)
	if err != nil {
		return secretstore.Secret{}, classify(err)
	}
	versionID := aws.ToString(out.VersionId)
	if out.SecretString != nil {
		return secretstore.NewStringSecret(*out.SecretString, versionID), nil
	}
	if out.SecretBinary != nil && utf8.Valid(out.SecretBinary) {
		return secretstore.NewStringSecret(string(out.SecretBinary), versionID), nil
	}
	return secretstore.Secret{}, fmt.Errorf("%w: the secret is binary", secretstore.ErrInvalidPayload)
}

// Probe implements secretstore.Backend: the credential chain yields
// credentials, without reading any secret.
func (b *Backend) Probe(ctx context.Context) error {
	if b.creds == nil {
		return fmt.Errorf("%w: no AWS credentials are configured", secretstore.ErrAuthFailed)
	}
	if _, err := b.creds.Retrieve(ctx); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("%w: retrieving AWS credentials timed out", secretstore.ErrUnavailable)
		}
		return fmt.Errorf("%w: retrieving AWS credentials failed", secretstore.ErrAuthFailed)
	}
	return nil
}

// classify maps a Secrets Manager error to its class. Only the error code is
// kept: messages can name the secret.
func classify(err error) error {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		code := apiErr.ErrorCode()
		switch code {
		case "ResourceNotFoundException", "InvalidRequestException", "InvalidParameterException":
			return fmt.Errorf("%w: %s", secretstore.ErrNotFound, code)
		case "AccessDeniedException", "DecryptionFailure":
			return fmt.Errorf("%w: %s", secretstore.ErrAccessDenied, code)
		case "UnrecognizedClientException", "InvalidSignatureException", "ExpiredTokenException",
			"InvalidClientTokenId", "IncompleteSignature", "MissingAuthenticationToken":
			return fmt.Errorf("%w: %s", secretstore.ErrAuthFailed, code)
		default:
			return fmt.Errorf("%w: %s", secretstore.ErrUnavailable, code)
		}
	}
	var signErr *v4.SigningError
	if errors.As(err, &signErr) {
		return fmt.Errorf("%w: retrieving AWS credentials failed", secretstore.ErrAuthFailed)
	}
	return fmt.Errorf("%w: Secrets Manager could not be reached", secretstore.ErrUnavailable)
}

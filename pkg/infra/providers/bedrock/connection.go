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

	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	smithy "github.com/aws/smithy-go"
)

func (c *client) TestConnection(ctx context.Context, cfg *providers.Config) providers.ProbeResult {
	awsCfg, err := buildAwsConfig(ctx, cfg.Credentials)
	if err != nil {
		return classifyAWSError(err)
	}

	stsClient := sts.NewFromConfig(awsCfg)
	if _, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}); err != nil {
		return classifyAWSError(err)
	}

	return providers.ProbeResult{OK: true, Stage: providers.StageAuthentication}
}

func classifyAWSError(err error) providers.ProbeResult {
	var statusErr interface{ HTTPStatusCode() int }
	if errors.As(err, &statusErr) {
		status := statusErr.HTTPStatusCode()
		if status == 401 || status == 403 {
			return providers.ProbeResult{
				OK:         false,
				Stage:      providers.StageAuthentication,
				StatusCode: status,
				Message:    "AWS rejected the credentials",
			}
		}
	}

	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		if isAuthErrorCode(apiErr.ErrorCode()) {
			return providers.ProbeResult{
				OK:      false,
				Stage:   providers.StageAuthentication,
				Message: "AWS rejected the credentials",
			}
		}
		return providers.ProbeResult{
			OK:      false,
			Stage:   providers.StageProvider,
			Message: fmt.Sprintf("AWS error: %s", apiErr.ErrorCode()),
		}
	}

	return providers.ProbeResult{
		OK:      false,
		Stage:   providers.StageConnectivity,
		Message: "could not reach AWS",
	}
}

func isAuthErrorCode(code string) bool {
	switch code {
	case "InvalidClientTokenId",
		"SignatureDoesNotMatch",
		"UnrecognizedClientException",
		"ExpiredToken",
		"ExpiredTokenException",
		"InvalidSignatureException",
		"AccessDenied",
		"AccessDeniedException",
		"AuthFailure":
		return true
	default:
		return false
	}
}

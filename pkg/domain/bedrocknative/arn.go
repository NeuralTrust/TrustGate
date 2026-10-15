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
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/domain/provider"
)

// BedrockARN is a parsed Bedrock model ARN: arn:<partition>:bedrock:<region>:<account>:<kind>/<resource>.
type BedrockARN struct {
	Partition string
	Region    string
	Account   string
	Kind      string
	Resource  string
}

// The resource kinds of a Bedrock model ARN.
const (
	KindFoundationModel    = "foundation-model"
	KindInferenceProfile   = "inference-profile"
	KindApplicationProfile = "application-inference-profile"
	KindProvisionedModel   = "provisioned-model"
	arnSections            = 6
	arnPartitionPrefix     = "aws"
	arnServiceBedrock      = "bedrock"
	arnScheme              = "arn"
)

// SplitBedrockARN splits the six sections of an ARN without judging them: the
// partition, region and account are whatever the string says, so a caller that
// builds anything from them must check them itself (provider.ValidAWSScope). It
// is for the callers that need the sections of an ARN a stricter parse refuses.
func SplitBedrockARN(s string) (BedrockARN, bool) {
	parts := strings.SplitN(s, ":", arnSections)
	if len(parts) != arnSections || parts[0] != arnScheme {
		return BedrockARN{}, false
	}
	kind, resource, _ := strings.Cut(parts[5], "/")
	return BedrockARN{Partition: parts[1], Region: parts[3], Account: parts[4], Kind: kind, Resource: resource}, true
}

// ParseBedrockARN parses the ARN of a Bedrock model resource. It is pure: no
// lookup, no network. A malformed ARN, another service and any partition that
// is not aws, aws-cn or aws-us-gov report ok=false.
func ParseBedrockARN(s string) (BedrockARN, bool) {
	parts := strings.SplitN(s, ":", arnSections)
	if len(parts) != arnSections || parts[2] != arnServiceBedrock {
		return BedrockARN{}, false
	}
	a, ok := SplitBedrockARN(s)
	if !ok || !strings.Contains(parts[5], "/") || a.Kind == "" || a.Resource == "" {
		return BedrockARN{}, false
	}
	switch a.Partition {
	case arnPartitionPrefix, "aws-cn", "aws-us-gov":
	default:
		return BedrockARN{}, false
	}
	if !provider.ValidAWSScope(a.Partition, a.Region, a.Account) {
		return BedrockARN{}, false
	}
	return a, true
}

// ModelID is the model identifier an ARN names without any lookup: a foundation
// model's ID, or a system-defined inference profile's ID, which still carries
// its geography ("us.", "eu.", "global.") for the usual prefix stripping.
func (a BedrockARN) ModelID() (string, bool) {
	switch a.Kind {
	case KindFoundationModel, KindInferenceProfile:
		return a.Resource, true
	}
	return "", false
}

// Opaque reports an ARN whose model can only be learned from the Bedrock
// control plane: an application inference profile or provisioned throughput.
func (a BedrockARN) Opaque() bool {
	return a.Kind == KindApplicationProfile || a.Kind == KindProvisionedModel
}

// ParseOpaqueBedrockARN is ParseBedrockARN for an ARN that needs a lookup.
func ParseOpaqueBedrockARN(s string) (BedrockARN, bool) {
	a, ok := ParseBedrockARN(s)
	return a, ok && a.Opaque()
}

// ModelIDFromModelARN reads the model identifier out of the foundation-model
// ARN the control plane returns for a profile or provisioned model.
func ModelIDFromModelARN(s string) (string, bool) {
	a, ok := ParseBedrockARN(s)
	if !ok {
		return "", false
	}
	return a.ModelID()
}

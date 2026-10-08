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
	"fmt"
	"net/url"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/domain/bedrocknative"
	"github.com/NeuralTrust/TrustGate/pkg/domain/provider"
)

// BedrockNativeOp is the Bedrock Runtime operation a native request calls.
type BedrockNativeOp = bedrocknative.Op

const (
	BedrockOpConverse       = bedrocknative.Converse
	BedrockOpConverseStream = bedrocknative.ConverseStream
	BedrockOpInvoke         = bedrocknative.Invoke
	BedrockOpInvokeStream   = bedrocknative.InvokeStream
)

const (
	bedrockNativeModelSegment = "/model/"
	bedrockModelIDMaxBytes    = 2048
	bedrockARNPrefix          = "arn:"
)

var (
	// ErrNotBedrockNativePath means the path is not shaped like a Bedrock
	// Runtime operation: it lacks the /model/ prefix or the operation segment.
	ErrNotBedrockNativePath = errors.New("path is not a native Bedrock Runtime route")
	// ErrInvalidBedrockModelID means the path is shaped like one, but the model
	// identifier in it is not one the gateway will write into an upstream path.
	ErrInvalidBedrockModelID = errors.New("invalid Bedrock model identifier")
)

// BedrockNativeRoute is a parsed /model/{modelId}/{operation} path. RawModelID
// is the segment exactly as the client sent it, ModelID the same segment
// percent-decoded; ARNs reach the gateway in either spelling.
type BedrockNativeRoute struct {
	Op         BedrockNativeOp
	RawModelID string
	ModelID    string
}

// IsStream reports whether the route's operation answers with an event stream.
func (r BedrockNativeRoute) IsStream() bool { return r.Op.IsStream() }

// ParseBedrockNativePath parses the part of a proxy path after the consumer
// slug, "/model/{modelId}/{operation}". The operation is the last segment and
// everything before it is the model identifier, which may hold raw slashes
// when it is an ARN. The caller must pass the path as received, still
// percent-encoded, because %2F and %3A are part of how an ARN is spelled.
func ParseBedrockNativePath(rest string) (BedrockNativeRoute, error) {
	if !strings.HasPrefix(rest, bedrockNativeModelSegment) {
		return BedrockNativeRoute{}, ErrNotBedrockNativePath
	}
	tail := rest[len(bedrockNativeModelSegment):]
	cut := strings.LastIndex(tail, "/")
	if cut < 0 {
		return BedrockNativeRoute{}, ErrNotBedrockNativePath
	}
	op := BedrockNativeOp(tail[cut+1:])
	if !op.Valid() {
		return BedrockNativeRoute{}, ErrNotBedrockNativePath
	}
	raw := tail[:cut]
	decoded, err := url.PathUnescape(raw)
	if err != nil {
		return BedrockNativeRoute{}, fmt.Errorf("%w: %s", ErrInvalidBedrockModelID, "bad percent-encoding")
	}
	if err := ValidateBedrockModelID(decoded); err != nil {
		return BedrockNativeRoute{}, err
	}
	return BedrockNativeRoute{Op: op, RawModelID: raw, ModelID: decoded}, nil
}

// ValidateBedrockModelID accepts the identifiers Bedrock documents: model IDs,
// inference profile IDs and ARNs. The value is written into the upstream path,
// so anything outside that alphabet, a dot segment, or a slash in a value that
// is not an ARN is refused rather than escaped.
func ValidateBedrockModelID(id string) error {
	switch {
	case id == "":
		return fmt.Errorf("%w: empty", ErrInvalidBedrockModelID)
	case len(id) > bedrockModelIDMaxBytes:
		return fmt.Errorf("%w: longer than %d bytes", ErrInvalidBedrockModelID, bedrockModelIDMaxBytes)
	}
	for i := range len(id) {
		if !isBedrockModelIDByte(id[i]) {
			return fmt.Errorf("%w: unsupported character", ErrInvalidBedrockModelID)
		}
	}
	if strings.Contains(id, "/") && !strings.HasPrefix(id, bedrockARNPrefix) {
		return fmt.Errorf("%w: only an ARN may contain '/'", ErrInvalidBedrockModelID)
	}
	if strings.HasPrefix(id, bedrockARNPrefix) {
		// An ARN names a partition, a region and an account, and code downstream
		// builds hosts from them: anything that is not an AWS scope is refused here.
		arn, ok := bedrocknative.SplitBedrockARN(id)
		if !ok || !provider.ValidAWSScope(arn.Partition, arn.Region, arn.Account) {
			return fmt.Errorf("%w: not an AWS partition, region and account", ErrInvalidBedrockModelID)
		}
	}
	for _, segment := range strings.Split(id, "/") {
		if segment == "." || segment == ".." {
			return fmt.Errorf("%w: dot segment", ErrInvalidBedrockModelID)
		}
	}
	return nil
}

func isBedrockModelIDByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		return true
	default:
		return strings.IndexByte("._:/-", b) >= 0
	}
}

// UpstreamPath returns the path and the raw (escaped) path to put on the
// upstream URL. The identifier is forwarded as received, except that a literal
// slash of a raw ARN becomes %2F: AWS reads an extra segment otherwise.
func (r BedrockNativeRoute) UpstreamPath() (path, rawPath string) {
	path = bedrockNativeModelSegment + r.ModelID + "/" + string(r.Op)
	rawPath = bedrockNativeModelSegment + strings.ReplaceAll(r.RawModelID, "/", "%2F") + "/" + string(r.Op)
	return path, rawPath
}

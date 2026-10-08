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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"iter"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
)

var _ providers.NativeBedrockClient = (*client)(nil)

const (
	// nativeSigningName is the SigV4 service name of the Bedrock Runtime API.
	nativeSigningName = "bedrock"

	headerContentType    = "Content-Type"
	headerAccept         = "Accept"
	headerAmznBedrockPfx = "X-Amzn-Bedrock-"
	headerAmznRequestID  = "X-Amzn-Requestid"
	nativeUserAgent      = "trustgate-bedrock-native"
)

var errNativeResponseTooLarge = errors.New("bedrock response exceeds the relay size limit")

// InvokeNative signs the request bytes as received with SigV4 and sends them to
// Bedrock Runtime, returning the status, body and allow-listed headers it got
// back. It reuses the pooled runtime client only for what it already resolved:
// credentials (AssumeRole and STS included), region, endpoint and the HTTP
// client, so a VPC endpoint or a test endpoint set on the client is honoured.
//
// Nothing is translated: the SDK serialiser, which would rebuild a Converse
// body and turn a stream into events, is not involved.
func (c *client) InvokeNative(
	ctx context.Context,
	cfg *providers.Config,
	req providers.NativeBedrockRequest,
) (*providers.NativeBedrockResponse, error) {
	rt, err := c.getOrCreateClient(ctx, cfg.Credentials)
	if err != nil {
		return nil, fmt.Errorf("failed to create Bedrock client: %w", err)
	}
	opts := rt.Options()
	if opts.Credentials == nil {
		return nil, errors.New("bedrock client has no credentials")
	}
	creds, err := opts.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve AWS credentials: %w", err)
	}
	endpoint, err := nativeEndpoint(ctx, opts)
	if err != nil {
		return nil, err
	}
	httpReq, err := nativeHTTPRequest(ctx, endpoint, req)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(req.Body)
	if err := v4.NewSigner().SignHTTP(ctx, creds, httpReq, hex.EncodeToString(sum[:]),
		nativeSigningName, opts.Region, time.Now()); err != nil {
		return nil, fmt.Errorf("failed to sign Bedrock request: %w", err)
	}

	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("bedrock request failed: %w", err)
	}
	out := &providers.NativeBedrockResponse{
		StatusCode: resp.StatusCode,
		Headers:    nativeResponseHeaders(resp.Header),
	}
	if req.Stream && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		out.Frames = nativeFrames(resp.Body)
		return out, nil
	}
	defer func() { _ = resp.Body.Close() }()
	limit := req.MaxResponseBytes
	if limit <= 0 {
		limit = config.DefaultBedrockNative().MaxResponseBytes
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read Bedrock response: %w", err)
	}
	if int64(len(body)) > limit {
		return nil, errNativeResponseTooLarge
	}
	out.Body = body
	return out, nil
}

func nativeEndpoint(ctx context.Context, opts bedrockruntime.Options) (*url.URL, error) {
	if opts.BaseEndpoint != nil && *opts.BaseEndpoint != "" {
		u, err := url.Parse(*opts.BaseEndpoint)
		if err != nil {
			return nil, fmt.Errorf("invalid Bedrock endpoint: %w", err)
		}
		return u, nil
	}
	resolver := opts.EndpointResolverV2
	if resolver == nil {
		resolver = bedrockruntime.NewDefaultEndpointResolverV2()
	}
	ep, err := resolver.ResolveEndpoint(ctx, bedrockruntime.EndpointParameters{
		Region:  aws.String(opts.Region),
		UseFIPS: aws.Bool(opts.EndpointOptions.UseFIPSEndpoint == aws.FIPSEndpointStateEnabled),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to resolve Bedrock endpoint: %w", err)
	}
	u := ep.URI
	return &u, nil
}

func nativeHTTPRequest(ctx context.Context, endpoint *url.URL, req providers.NativeBedrockRequest) (*http.Request, error) {
	target := *endpoint
	target.Path = strings.TrimRight(endpoint.Path, "/") + req.Path
	target.RawPath = ""
	if req.RawPath != "" {
		target.RawPath = strings.TrimRight(endpoint.EscapedPath(), "/") + req.RawPath
	}
	target.RawQuery, target.Fragment = "", ""
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(req.Body))
	if err != nil {
		return nil, fmt.Errorf("failed to build Bedrock request: %w", err)
	}
	httpReq.Header = nativeRequestHeaders(req.Headers)
	return httpReq, nil
}

// nativeRequestHeaders keeps the client headers Bedrock gives meaning to:
// Content-Type, Accept and the X-Amzn-Bedrock-* family (guardrail, trace,
// performance and service-tier knobs). Everything else is the client's own
// credentials, the gateway's headers or hop-by-hop noise, and none of it may
// reach AWS; the request is signed with the registry's credentials instead.
func nativeRequestHeaders(in http.Header) http.Header {
	out := http.Header{}
	for name, values := range in {
		canonical := textproto.CanonicalMIMEHeaderKey(name)
		switch {
		case canonical == headerContentType, canonical == headerAccept,
			strings.HasPrefix(canonical, headerAmznBedrockPfx):
			out[canonical] = append([]string(nil), values...)
		}
	}
	if out.Get(headerContentType) == "" {
		out.Set(headerContentType, "application/json")
	}
	out.Set("User-Agent", nativeUserAgent)
	return out
}

func nativeResponseHeaders(in http.Header) http.Header {
	out := http.Header{}
	for name, values := range in {
		canonical := textproto.CanonicalMIMEHeaderKey(name)
		switch {
		case canonical == headerContentType, canonical == headerAmznRequestID, canonical == adapter.HeaderAmznErrorType,
			strings.HasPrefix(canonical, headerAmznBedrockPfx):
			out[canonical] = append([]string(nil), values...)
		}
	}
	return out
}

func nativeFrames(body io.ReadCloser) iter.Seq2[[]byte, error] {
	return func(yield func([]byte, error) bool) {
		defer func() { _ = body.Close() }()
		for {
			frame, err := adapter.ReadBedrockFrame(body, adapter.BedrockFrameMaxBytes)
			if errors.Is(err, io.EOF) {
				return
			}
			if err != nil {
				yield(nil, err)
				return
			}
			if !yield(frame, nil) {
				return
			}
		}
	}
}

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
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	nativeTestAccessKey = "AKIAFUNCTIONALTEST"
	nativeTestSecretKey = "native-test-secret"
	nativeTestRegion    = "us-east-1"
)

type capturedRequest struct {
	RequestURI string
	Header     http.Header
	Body       []byte
	URL        url.URL
	Host       string
}

type nativeUpstream struct {
	*httptest.Server
	mu   sync.Mutex
	seen []capturedRequest
}

func (u *nativeUpstream) last(t *testing.T) capturedRequest {
	t.Helper()
	u.mu.Lock()
	defer u.mu.Unlock()
	require.NotEmpty(t, u.seen, "upstream saw no request")
	return u.seen[len(u.seen)-1]
}

func newNativeUpstream(t *testing.T, handler func(w http.ResponseWriter, r *http.Request)) *nativeUpstream {
	t.Helper()
	up := &nativeUpstream{}
	up.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		up.mu.Lock()
		up.seen = append(up.seen, capturedRequest{
			RequestURI: r.RequestURI, Header: r.Header.Clone(), Body: body, URL: *r.URL, Host: r.Host,
		})
		up.mu.Unlock()
		handler(w, r)
	}))
	t.Cleanup(up.Close)
	return up
}

// nativeClient returns a client whose pooled runtime client points at endpoint,
// the way AWS_ENDPOINT_URL_BEDROCK_RUNTIME or a VPC endpoint would.
func nativeClient(t *testing.T, endpoint string) (*client, *providers.Config) {
	t.Helper()
	cfg := &providers.Config{Credentials: providers.Credentials{AwsBedrock: &providers.AwsBedrock{
		Region: nativeTestRegion, AccessKey: nativeTestAccessKey, SecretKey: nativeTestSecretKey,
	}}}
	c := &client{clientPool: &sync.Map{}}
	opts := bedrockruntime.Options{
		Region:      nativeTestRegion,
		Credentials: credentials.NewStaticCredentialsProvider(nativeTestAccessKey, nativeTestSecretKey, ""),
		HTTPClient:  http.DefaultClient,
	}
	if endpoint != "" {
		opts.BaseEndpoint = aws.String(endpoint)
	}
	c.clientPool.Store(buildClientKey(cfg.Credentials), bedrockruntime.New(opts))
	return c, cfg
}

// verifySignature re-signs the request exactly as the upstream received it and
// compares: a path or header that changed between signing and the wire fails.
func verifySignature(t *testing.T, got capturedRequest) {
	t.Helper()
	auth := got.Header.Get("Authorization")
	require.True(t, strings.HasPrefix(auth, "AWS4-HMAC-SHA256 "), auth)
	require.Contains(t, auth, "/"+nativeTestRegion+"/bedrock/aws4_request")
	_, rest, _ := strings.Cut(auth, "SignedHeaders=")
	signed, _, _ := strings.Cut(rest, ",")

	re := &http.Request{
		Method: http.MethodPost, Host: got.Host, Header: http.Header{}, ContentLength: int64(len(got.Body)),
		URL: &url.URL{Scheme: "http", Host: got.Host, Path: got.URL.Path, RawPath: got.URL.RawPath},
	}
	for _, name := range strings.Split(signed, ";") {
		if name != "host" {
			re.Header.Set(name, got.Header.Get(name))
		}
	}
	signedAt, err := time.Parse("20060102T150405Z", got.Header.Get("X-Amz-Date"))
	require.NoError(t, err)
	sum := sha256.Sum256(got.Body)
	require.NoError(t, v4.NewSigner().SignHTTP(context.Background(),
		aws.Credentials{AccessKeyID: nativeTestAccessKey, SecretAccessKey: nativeTestSecretKey},
		re, hex.EncodeToString(sum[:]), "bedrock", nativeTestRegion, signedAt))
	assert.Equal(t, re.Header.Get("Authorization"), auth, "signature does not match the request on the wire")
}

func clientHeaders() http.Header {
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	h.Set("Accept", "application/json")
	h.Set("X-Amzn-Bedrock-Trace", "ENABLED")
	h.Set("Authorization", "AWS4-HMAC-SHA256 Credential=CLIENT/20260101/us-east-1/bedrock/aws4_request, Signature=beef")
	h.Set("X-Amz-Security-Token", "client-session-token")
	h.Set("X-Amz-Date", "20200101T000000Z")
	h.Set("X-Amz-Content-Sha256", "client-hash")
	h.Set("X-AG-API-Key", "ag_secret")
	h.Set("X-Api-Key", "client-key")
	h.Set("X-Goog-Api-Key", "client-key")
	h.Set("Cookie", "session=1")
	h.Set("Amz-Sdk-Invocation-Id", "abc")
	h.Set("User-Agent", "Boto3/1.0")
	return h
}

func TestInvokeNative_RelaysBytesAndHeaders(t *testing.T) {
	t.Parallel()
	up := newNativeUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Amzn-Bedrock-Input-Token-Count", "11")
		w.Header().Set("X-Amzn-Bedrock-Output-Token-Count", "7")
		w.Header().Set("X-Amzn-RequestId", "req-123")
		w.Header().Set("Set-Cookie", "leak=1")
		w.Header().Set("Server", "aws")
		_, _ = io.WriteString(w, `{"output":{"message":{"role":"assistant","content":[{"text":"ok"}]}}}`)
	})
	c, cfg := nativeClient(t, up.URL)
	// Whitespace and key order that a re-serialiser would normalise.
	body := []byte("{ \"messages\" : [ {\"role\":\"user\",  \"content\":[{\"text\":\"hi\"}]} ],\"zzz\":1,\"aaa\":2 }")

	resp, err := c.InvokeNative(context.Background(), cfg, providers.NativeBedrockRequest{
		Path:    "/model/amazon.nova-lite-v1:0/converse",
		RawPath: "/model/amazon.nova-lite-v1%3A0/converse",
		Body:    body,
		Headers: clientHeaders(),
	})
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, `{"output":{"message":{"role":"assistant","content":[{"text":"ok"}]}}}`, string(resp.Body))
	assert.Nil(t, resp.Frames)

	got := up.last(t)
	assert.Equal(t, body, got.Body, "the body must reach AWS byte for byte")
	assert.Equal(t, "/model/amazon.nova-lite-v1%3A0/converse", got.RequestURI, "the encoded identifier is forwarded as received")
	assert.Equal(t, "application/json", got.Header.Get("Content-Type"))
	assert.Equal(t, "application/json", got.Header.Get("Accept"))
	assert.Equal(t, "ENABLED", got.Header.Get("X-Amzn-Bedrock-Trace"))
	verifySignature(t, got)

	for _, leaked := range []string{
		"X-Amz-Security-Token", "X-Amz-Content-Sha256", "X-Ag-Api-Key", "X-Api-Key", "X-Goog-Api-Key",
		"Cookie", "Amz-Sdk-Invocation-Id",
	} {
		assert.Empty(t, got.Header.Get(leaked), "%s must not reach AWS", leaked)
	}
	assert.NotContains(t, got.Header.Get("Authorization"), "CLIENT", "the client's own signature must not be forwarded")
	assert.NotEqual(t, "20200101T000000Z", got.Header.Get("X-Amz-Date"))
	assert.NotContains(t, got.Header.Get("User-Agent"), "Boto3")

	assert.Equal(t, "application/json", resp.Headers.Get("Content-Type"))
	assert.Equal(t, "11", resp.Headers.Get("X-Amzn-Bedrock-Input-Token-Count"))
	assert.Equal(t, "7", resp.Headers.Get("X-Amzn-Bedrock-Output-Token-Count"))
	assert.Equal(t, "req-123", resp.Headers.Get("X-Amzn-RequestId"))
	assert.Empty(t, resp.Headers.Get("Set-Cookie"))
	assert.Empty(t, resp.Headers.Get("Server"))
}

func TestInvokeNative_DefaultsTheContentType(t *testing.T) {
	t.Parallel()
	up := newNativeUpstream(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{}`) })
	c, cfg := nativeClient(t, up.URL)
	_, err := c.InvokeNative(context.Background(), cfg, providers.NativeBedrockRequest{
		Path: "/model/m/invoke", RawPath: "/model/m/invoke", Body: []byte(`{}`),
	})
	require.NoError(t, err)
	assert.Equal(t, "application/json", up.last(t).Header.Get("Content-Type"))
}

func TestInvokeNative_ARNPathStaysSignedAndEncoded(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		route   adapter.BedrockNativeRoute
		wantURI string
	}{
		{
			name: "encoded ARN is forwarded as received",
			route: adapter.BedrockNativeRoute{
				Op:         adapter.BedrockOpConverse,
				RawModelID: "arn%3Aaws%3Abedrock%3Aus-east-1%3A123456789012%3Ainference-profile%2Fus.anthropic.claude-3-5-sonnet-20241022-v2%3A0",
				ModelID:    "arn:aws:bedrock:us-east-1:123456789012:inference-profile/us.anthropic.claude-3-5-sonnet-20241022-v2:0",
			},
			wantURI: "/model/arn%3Aaws%3Abedrock%3Aus-east-1%3A123456789012%3Ainference-profile%2Fus.anthropic.claude-3-5-sonnet-20241022-v2%3A0/converse",
		},
		{
			name: "raw slash of an ARN is escaped, nothing else changes",
			route: adapter.BedrockNativeRoute{
				Op:         adapter.BedrockOpInvoke,
				RawModelID: "arn:aws:bedrock:us-east-1:123456789012:inference-profile/us.anthropic.claude-3-5-sonnet-20241022-v2:0",
				ModelID:    "arn:aws:bedrock:us-east-1:123456789012:inference-profile/us.anthropic.claude-3-5-sonnet-20241022-v2:0",
			},
			wantURI: "/model/arn:aws:bedrock:us-east-1:123456789012:inference-profile%2Fus.anthropic.claude-3-5-sonnet-20241022-v2:0/invoke",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			up := newNativeUpstream(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{}`) })
			c, cfg := nativeClient(t, up.URL)
			path, raw := tc.route.UpstreamPath()
			_, err := c.InvokeNative(context.Background(), cfg, providers.NativeBedrockRequest{Path: path, RawPath: raw, Body: []byte(`{}`)})
			require.NoError(t, err)
			got := up.last(t)
			assert.Equal(t, tc.wantURI, got.RequestURI)
			verifySignature(t, got)
		})
	}
}

func TestInvokeNative_RelaysAWSErrorsUnchanged(t *testing.T) {
	t.Parallel()
	const awsBody = `{"message":"Malformed input request: extraneous key [foo] is not permitted"}`
	up := newNativeUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Amzn-ErrorType", "ValidationException:http://internal.amazon.com/coral/")
		w.Header().Set("X-Amzn-RequestId", "req-err")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, awsBody)
	})
	c, cfg := nativeClient(t, up.URL)

	for _, stream := range []bool{false, true} {
		resp, err := c.InvokeNative(context.Background(), cfg, providers.NativeBedrockRequest{
			Path: "/model/m/converse", RawPath: "/model/m/converse", Body: []byte(`{}`), Stream: stream,
		})
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Equal(t, awsBody, string(resp.Body), "a 4xx is read whole even on a stream operation")
		assert.Nil(t, resp.Frames)
		assert.Equal(t, "ValidationException:http://internal.amazon.com/coral/", resp.Headers.Get("X-Amzn-ErrorType"))
		assert.Equal(t, "req-err", resp.Headers.Get("X-Amzn-RequestId"))
	}
}

func testFrames(t *testing.T) [][]byte {
	t.Helper()
	return [][]byte{
		adapter.BedrockExceptionFrame("modelStreamErrorException", "first"),
		adapter.BedrockExceptionFrame("modelStreamErrorException", "second, a little longer than the first"),
		adapter.BedrockExceptionFrame("modelStreamErrorException", "third"),
	}
}

func TestInvokeNative_StreamYieldsRawFrames(t *testing.T) {
	t.Parallel()
	frames := testFrames(t)
	up := newNativeUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.amazon.eventstream")
		w.WriteHeader(http.StatusOK)
		for _, f := range frames {
			_, _ = w.Write(f)
			w.(http.Flusher).Flush()
		}
	})
	c, cfg := nativeClient(t, up.URL)

	resp, err := c.InvokeNative(context.Background(), cfg, providers.NativeBedrockRequest{
		Path: "/model/m/converse-stream", RawPath: "/model/m/converse-stream", Body: []byte(`{}`), Stream: true,
	})
	require.NoError(t, err)
	require.NotNil(t, resp.Frames)
	assert.Equal(t, "application/vnd.amazon.eventstream", resp.Headers.Get("Content-Type"))

	var got [][]byte
	for frame, ferr := range resp.Frames {
		require.NoError(t, ferr)
		got = append(got, frame)
	}
	assert.Equal(t, frames, got, "every frame must arrive identical")
	verifySignature(t, up.last(t))
}

func TestInvokeNative_StreamReportsATruncatedFrame(t *testing.T) {
	t.Parallel()
	frames := testFrames(t)
	up := newNativeUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(frames[0])
		_, _ = w.Write(frames[1][:len(frames[1])-4])
	})
	c, cfg := nativeClient(t, up.URL)
	resp, err := c.InvokeNative(context.Background(), cfg, providers.NativeBedrockRequest{
		Path: "/model/m/converse-stream", RawPath: "/model/m/converse-stream", Body: []byte(`{}`), Stream: true,
	})
	require.NoError(t, err)

	var n int
	var streamErr error
	for _, ferr := range resp.Frames {
		if ferr != nil {
			streamErr = ferr
			break
		}
		n++
	}
	assert.Equal(t, 1, n)
	assert.ErrorIs(t, streamErr, io.ErrUnexpectedEOF)
}

func TestInvokeNative_StreamStopsWhenTheConsumerDoes(t *testing.T) {
	t.Parallel()
	frames := testFrames(t)
	released := make(chan struct{})
	up := newNativeUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(frames[0])
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		close(released)
	})
	c, cfg := nativeClient(t, up.URL)
	resp, err := c.InvokeNative(context.Background(), cfg, providers.NativeBedrockRequest{
		Path: "/model/m/converse-stream", RawPath: "/model/m/converse-stream", Body: []byte(`{}`), Stream: true,
	})
	require.NoError(t, err)
	for range resp.Frames {
		break
	}
	select {
	case <-released:
	case <-time.After(5 * time.Second):
		t.Fatal("stopping the consumer must close the upstream body")
	}
}

func TestInvokeNative_RefusesAnOversizedBufferedAnswer(t *testing.T) {
	t.Parallel()
	up := newNativeUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("a"), int(config.DefaultBedrockNative().MaxResponseBytes)+1))
	})
	c, cfg := nativeClient(t, up.URL)
	_, err := c.InvokeNative(context.Background(), cfg, providers.NativeBedrockRequest{
		Path: "/model/m/invoke", RawPath: "/model/m/invoke", Body: []byte(`{}`),
	})
	assert.ErrorIs(t, err, errNativeResponseTooLarge)
}

func TestInvokeNative_HonoursAConfiguredResponseLimit(t *testing.T) {
	t.Parallel()
	up := newNativeUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("a"), 1025))
	})
	c, cfg := nativeClient(t, up.URL)
	_, err := c.InvokeNative(context.Background(), cfg, providers.NativeBedrockRequest{
		Path: "/model/m/invoke", RawPath: "/model/m/invoke", Body: []byte(`{}`), MaxResponseBytes: 1024,
	})
	assert.ErrorIs(t, err, errNativeResponseTooLarge)

	resp, err := c.InvokeNative(context.Background(), cfg, providers.NativeBedrockRequest{
		Path: "/model/m/invoke", RawPath: "/model/m/invoke", Body: []byte(`{}`), MaxResponseBytes: 2048,
	})
	require.NoError(t, err)
	assert.Len(t, resp.Body, 1025)
}

func TestInvokeNative_TransportFailureIsAnError(t *testing.T) {
	t.Parallel()
	up := newNativeUpstream(t, func(http.ResponseWriter, *http.Request) {})
	endpoint := up.URL
	up.Close()
	c, cfg := nativeClient(t, endpoint)
	_, err := c.InvokeNative(context.Background(), cfg, providers.NativeBedrockRequest{
		Path: "/model/m/invoke", RawPath: "/model/m/invoke", Body: []byte(`{}`),
	})
	assert.Error(t, err)
}

func TestNativeEndpoint(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("base endpoint wins", func(t *testing.T) {
		t.Parallel()
		u, err := nativeEndpoint(ctx, bedrockruntime.Options{Region: "us-east-1", BaseEndpoint: aws.String("https://vpce.example.internal:8443/prefix")})
		require.NoError(t, err)
		assert.Equal(t, "https://vpce.example.internal:8443/prefix", u.String())
	})
	t.Run("regional default", func(t *testing.T) {
		t.Parallel()
		u, err := nativeEndpoint(ctx, bedrockruntime.Options{Region: "eu-west-1"})
		require.NoError(t, err)
		assert.Equal(t, "bedrock-runtime.eu-west-1.amazonaws.com", u.Host)
	})
	t.Run("china partition", func(t *testing.T) {
		t.Parallel()
		u, err := nativeEndpoint(ctx, bedrockruntime.Options{Region: "cn-north-1"})
		require.NoError(t, err)
		assert.Equal(t, "bedrock-runtime.cn-north-1.amazonaws.com.cn", u.Host)
	})
	t.Run("fips", func(t *testing.T) {
		t.Parallel()
		opts := bedrockruntime.Options{Region: "us-gov-west-1"}
		opts.EndpointOptions.UseFIPSEndpoint = aws.FIPSEndpointStateEnabled
		u, err := nativeEndpoint(ctx, opts)
		require.NoError(t, err)
		assert.Contains(t, u.Host, "fips")
	})
	t.Run("invalid base endpoint", func(t *testing.T) {
		t.Parallel()
		_, err := nativeEndpoint(ctx, bedrockruntime.Options{BaseEndpoint: aws.String("http://bad host/")})
		assert.Error(t, err)
	})
}

func TestNativeRequestHeaders_AllowList(t *testing.T) {
	t.Parallel()
	got := nativeRequestHeaders(clientHeaders())
	assert.ElementsMatch(t, []string{"Content-Type", "Accept", "X-Amzn-Bedrock-Trace", "User-Agent"}, headerNames(got))
}

func headerNames(h http.Header) []string {
	names := make([]string, 0, len(h))
	for name := range h {
		names = append(names, name)
	}
	return names
}

// TCP gives no frame boundaries: a frame can arrive a byte at a time, and it
// must still come out whole and identical.
func TestInvokeNative_StreamReassemblesFramesSplitAcrossReads(t *testing.T) {
	t.Parallel()
	frames := testFrames(t)
	up := newNativeUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		for _, f := range frames {
			for i := range f {
				_, _ = w.Write(f[i : i+1])
				w.(http.Flusher).Flush()
			}
		}
	})
	c, cfg := nativeClient(t, up.URL)
	resp, err := c.InvokeNative(context.Background(), cfg, providers.NativeBedrockRequest{
		Path: "/model/m/converse-stream", RawPath: "/model/m/converse-stream", Body: []byte(`{}`), Stream: true,
	})
	require.NoError(t, err)
	var got [][]byte
	for frame, ferr := range resp.Frames {
		require.NoError(t, ferr)
		got = append(got, frame)
	}
	assert.Equal(t, frames, got)
}

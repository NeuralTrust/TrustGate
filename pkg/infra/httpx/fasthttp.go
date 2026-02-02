package httpx

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/valyala/fasthttp"
)

// Default values for FastHTTPClient options
const (
	DefaultTimeout             = 30 * time.Second
	DefaultMaxConnsPerHost     = 512
	DefaultMaxIdleConnDuration = 10 * time.Second
	DefaultReadBufferSize      = 4096
	DefaultWriteBufferSize     = 4096
	DefaultMaxResponseBodySize = 100 * 1024 * 1024 // 100MB
)

// FastHTTPClientOptions contains configuration for the FastHTTP client
type FastHTTPClientOptions struct {
	// Timeout is the maximum duration for the entire request (read + write)
	Timeout time.Duration

	// ReadTimeout is the maximum duration for reading the full response
	ReadTimeout time.Duration

	// WriteTimeout is the maximum duration for writing the full request
	WriteTimeout time.Duration

	// InsecureSkipVerify controls whether to skip TLS certificate verification
	InsecureSkipVerify bool

	// MaxConnsPerHost is the maximum number of concurrent connections per host
	MaxConnsPerHost int

	// MaxIdleConnDuration is the maximum duration for keeping idle connections open
	MaxIdleConnDuration time.Duration

	// ReadBufferSize is the size of the read buffer
	ReadBufferSize int

	// WriteBufferSize is the size of the write buffer
	WriteBufferSize int

	// MaxResponseBodySize is the maximum response body size to read
	MaxResponseBodySize int

	// UserAgent is the default User-Agent header value
	UserAgent string
}

// FastHTTPClientOption is a function that configures FastHTTPClientOptions
type FastHTTPClientOption func(*FastHTTPClientOptions)

// WithTimeout sets the overall request timeout
func WithTimeout(timeout time.Duration) FastHTTPClientOption {
	return func(o *FastHTTPClientOptions) {
		o.Timeout = timeout
	}
}

// WithReadTimeout sets the read timeout
func WithReadTimeout(timeout time.Duration) FastHTTPClientOption {
	return func(o *FastHTTPClientOptions) {
		o.ReadTimeout = timeout
	}
}

// WithWriteTimeout sets the write timeout
func WithWriteTimeout(timeout time.Duration) FastHTTPClientOption {
	return func(o *FastHTTPClientOptions) {
		o.WriteTimeout = timeout
	}
}

// WithInsecureSkipVerify sets whether to skip TLS certificate verification
func WithInsecureSkipVerify(skip bool) FastHTTPClientOption {
	return func(o *FastHTTPClientOptions) {
		o.InsecureSkipVerify = skip
	}
}

// WithMaxConnsPerHost sets the maximum connections per host
func WithMaxConnsPerHost(max int) FastHTTPClientOption {
	return func(o *FastHTTPClientOptions) {
		o.MaxConnsPerHost = max
	}
}

// WithMaxIdleConnDuration sets the maximum idle connection duration
func WithMaxIdleConnDuration(duration time.Duration) FastHTTPClientOption {
	return func(o *FastHTTPClientOptions) {
		o.MaxIdleConnDuration = duration
	}
}

// WithReadBufferSize sets the read buffer size
func WithReadBufferSize(size int) FastHTTPClientOption {
	return func(o *FastHTTPClientOptions) {
		o.ReadBufferSize = size
	}
}

// WithWriteBufferSize sets the write buffer size
func WithWriteBufferSize(size int) FastHTTPClientOption {
	return func(o *FastHTTPClientOptions) {
		o.WriteBufferSize = size
	}
}

// WithMaxResponseBodySize sets the maximum response body size
func WithMaxResponseBodySize(size int) FastHTTPClientOption {
	return func(o *FastHTTPClientOptions) {
		o.MaxResponseBodySize = size
	}
}

// WithUserAgent sets the default User-Agent header
func WithUserAgent(userAgent string) FastHTTPClientOption {
	return func(o *FastHTTPClientOptions) {
		o.UserAgent = userAgent
	}
}

type FastHTTPClient struct {
	client    *fasthttp.Client
	userAgent string
}

// NewFastHTTPClient creates a new FastHTTPClient with the given options.
// If no options are provided, sensible defaults are used.
func NewFastHTTPClient(opts ...FastHTTPClientOption) Client {
	options := &FastHTTPClientOptions{
		Timeout:             DefaultTimeout,
		MaxConnsPerHost:     DefaultMaxConnsPerHost,
		MaxIdleConnDuration: DefaultMaxIdleConnDuration,
		ReadBufferSize:      DefaultReadBufferSize,
		WriteBufferSize:     DefaultWriteBufferSize,
		MaxResponseBodySize: DefaultMaxResponseBodySize,
	}

	for _, opt := range opts {
		opt(options)
	}

	client := &fasthttp.Client{
		MaxConnsPerHost:     options.MaxConnsPerHost,
		MaxIdleConnDuration: options.MaxIdleConnDuration,
		ReadBufferSize:      options.ReadBufferSize,
		WriteBufferSize:     options.WriteBufferSize,
		MaxResponseBodySize: options.MaxResponseBodySize,
	}

	// Set timeouts
	if options.ReadTimeout > 0 {
		client.ReadTimeout = options.ReadTimeout
	} else if options.Timeout > 0 {
		client.ReadTimeout = options.Timeout
	}

	if options.WriteTimeout > 0 {
		client.WriteTimeout = options.WriteTimeout
	} else if options.Timeout > 0 {
		client.WriteTimeout = options.Timeout
	}

	// Configure TLS if InsecureSkipVerify is set
	if options.InsecureSkipVerify {
		client.TLSConfig = &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // intentionally configurable
		}
	}

	return &FastHTTPClient{
		client:    client,
		userAgent: options.UserAgent,
	}
}

// NewFastHTTPClientWithClient creates a FastHTTPClient with a pre-configured fasthttp.Client.
// Deprecated: Use NewFastHTTPClient with options instead.
func NewFastHTTPClientWithClient(client *fasthttp.Client) Client {
	if client == nil {
		return NewFastHTTPClient()
	}
	return &FastHTTPClient{
		client: client,
	}
}

// FastHTTPClientConfig provides a simple configuration struct for creating a FastHTTPClient.
// This is an alternative to using functional options.
type FastHTTPClientConfig struct {
	Timeout            time.Duration
	InsecureSkipVerify bool
	MaxConnsPerHost    int
	UserAgent          string
}

// NewFastHTTPClientWithConfig creates a FastHTTPClient using a config struct.
// This is a convenience method for external packages that prefer struct-based configuration.
func NewFastHTTPClientWithConfig(cfg FastHTTPClientConfig) Client {
	var opts []FastHTTPClientOption

	if cfg.Timeout > 0 {
		opts = append(opts, WithTimeout(cfg.Timeout))
	}
	if cfg.InsecureSkipVerify {
		opts = append(opts, WithInsecureSkipVerify(true))
	}
	if cfg.MaxConnsPerHost > 0 {
		opts = append(opts, WithMaxConnsPerHost(cfg.MaxConnsPerHost))
	}
	if cfg.UserAgent != "" {
		opts = append(opts, WithUserAgent(cfg.UserAgent))
	}

	return NewFastHTTPClient(opts...)
}

func (c *FastHTTPClient) Do(req *http.Request) (*http.Response, error) {
	fastReq := fasthttp.AcquireRequest()
	fastResp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(fastReq)

	// Set URI - use URI() for better performance when possible
	if req.URL != nil {
		fastReq.SetRequestURI(req.URL.String())
	}

	// Set method
	fastReq.Header.SetMethod(req.Method)

	// Set Host header first (before other headers that might override it)
	if req.Host != "" {
		fastReq.Header.SetHost(req.Host)
	} else if req.URL != nil && req.URL.Host != "" {
		fastReq.Header.SetHost(req.URL.Host)
	}

	// Copy headers - use Set for single values, Add for multiple
	for key, values := range req.Header {
		if len(values) == 1 {
			fastReq.Header.Set(key, values[0])
		} else {
			for _, value := range values {
				fastReq.Header.Add(key, value)
			}
		}
	}

	// Set default User-Agent if configured and not already set in request
	if c.userAgent != "" && len(req.Header.Get("User-Agent")) == 0 {
		fastReq.Header.Set("User-Agent", c.userAgent)
	}

	// Set request body
	if req.Body != nil {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read request body: %w", err)
		}
		// Use SetBodyRaw to avoid extra copy (fasthttp will not modify it)
		fastReq.SetBodyRaw(body)
		// Always close the body
		_ = req.Body.Close()
	}

	// Execute request
	if err := c.client.Do(fastReq, fastResp); err != nil {
		fasthttp.ReleaseResponse(fastResp)
		return nil, err
	}

	// Build response - MUST copy body before releasing fastResp
	// fastResp.Body() returns a reference to internal buffer that will be reused
	respBody := fastResp.Body()
	bodyCopy := make([]byte, len(respBody))
	copy(bodyCopy, respBody)

	statusCode := fastResp.StatusCode()

	// Pre-allocate header map with estimated size
	headerCount := 0
	fastResp.Header.VisitAll(func(_, _ []byte) { headerCount++ })
	headers := make(http.Header, headerCount)

	// Copy headers with proper canonical formatting
	fastResp.Header.VisitAll(func(key, value []byte) {
		// http.Header.Add handles canonical key conversion
		headers.Add(string(key), string(value))
	})

	// Get content length
	contentLength := int64(len(bodyCopy))
	if cl := fastResp.Header.ContentLength(); cl >= 0 {
		contentLength = int64(cl)
	}

	// Build the response
	resp := &http.Response{
		Status:        fmt.Sprintf("%d %s", statusCode, http.StatusText(statusCode)),
		StatusCode:    statusCode,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        headers,
		Body:          io.NopCloser(bytes.NewReader(bodyCopy)),
		ContentLength: contentLength,
		Request:       req,
	}

	// Now safe to release the response
	fasthttp.ReleaseResponse(fastResp)

	return resp, nil
}

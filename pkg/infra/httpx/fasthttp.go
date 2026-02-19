package httpx

import (
	"bytes"
	"crypto/tls"
	"io"
	"net/http"
	"time"

	"github.com/valyala/fasthttp"
)

const (
	DefaultTimeout             = 30 * time.Second
	DefaultMaxConnsPerHost     = 512
	DefaultMaxIdleConnDuration = 10 * time.Second
)

type FastHTTPClientOptions struct {
	Timeout             time.Duration
	InsecureSkipVerify  bool
	MaxConnsPerHost     int
	MaxIdleConnDuration time.Duration
}

type FastHTTPClientOption func(*FastHTTPClientOptions)

func WithTimeout(timeout time.Duration) FastHTTPClientOption {
	return func(o *FastHTTPClientOptions) {
		o.Timeout = timeout
	}
}

func WithInsecureSkipVerify(skip bool) FastHTTPClientOption {
	return func(o *FastHTTPClientOptions) {
		o.InsecureSkipVerify = skip
	}
}

func WithMaxConnsPerHost(max int) FastHTTPClientOption {
	return func(o *FastHTTPClientOptions) {
		o.MaxConnsPerHost = max
	}
}

func WithMaxIdleConnDuration(duration time.Duration) FastHTTPClientOption {
	return func(o *FastHTTPClientOptions) {
		o.MaxIdleConnDuration = duration
	}
}

type FastHTTPClient struct {
	client *fasthttp.Client
}

func NewFastHTTPClient(opts ...FastHTTPClientOption) Client {
	options := &FastHTTPClientOptions{
		Timeout:             DefaultTimeout,
		MaxConnsPerHost:     DefaultMaxConnsPerHost,
		MaxIdleConnDuration: DefaultMaxIdleConnDuration,
	}

	for _, opt := range opts {
		opt(options)
	}

	client := &fasthttp.Client{
		MaxConnsPerHost:     options.MaxConnsPerHost,
		MaxIdleConnDuration: options.MaxIdleConnDuration,
	}

	if options.Timeout > 0 {
		client.ReadTimeout = options.Timeout
		client.WriteTimeout = options.Timeout
	}

	if options.InsecureSkipVerify {
		client.TLSConfig = &tls.Config{
			InsecureSkipVerify: true, //#nosec G402
		}
	}

	return &FastHTTPClient{client: client}
}

func (c *FastHTTPClient) Do(req *http.Request) (*http.Response, error) {
	fastReq := fasthttp.AcquireRequest()
	fastResp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(fastReq)

	if req.URL != nil {
		fastReq.SetRequestURI(req.URL.String())
	}

	fastReq.Header.SetMethod(req.Method)

	if req.Host != "" {
		fastReq.Header.SetHost(req.Host)
	} else if req.URL != nil {
		fastReq.Header.SetHost(req.URL.Host)
	}

	for key, values := range req.Header {
		for _, value := range values {
			fastReq.Header.Set(key, value)
		}
	}

	if req.Body != nil {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			fasthttp.ReleaseResponse(fastResp)
			return nil, err
		}
		fastReq.SetBodyRaw(body)
		_ = req.Body.Close()
	}

	if err := c.client.Do(fastReq, fastResp); err != nil {
		fasthttp.ReleaseResponse(fastResp)
		return nil, err
	}

	respBody := fastResp.Body()
	bodyCopy := make([]byte, len(respBody))
	copy(bodyCopy, respBody)

	statusCode := fastResp.StatusCode()

	headers := make(http.Header, 8)
	fastResp.Header.VisitAll(func(key, value []byte) {
		headers.Set(string(key), string(value))
	})

	resp := &http.Response{
		StatusCode:    statusCode,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        headers,
		Body:          io.NopCloser(bytes.NewReader(bodyCopy)),
		ContentLength: int64(len(bodyCopy)),
		Request:       req,
	}

	fasthttp.ReleaseResponse(fastResp)

	return resp, nil
}

package httpx

import (
	"crypto/tls"
	"net/http"
	"time"
)

type StdHTTPClientOptions struct {
	Timeout            time.Duration
	Transport          http.RoundTripper
	InsecureSkipVerify bool
}

type StdHTTPClientOption func(*StdHTTPClientOptions)

func WithStdTimeout(timeout time.Duration) StdHTTPClientOption {
	return func(o *StdHTTPClientOptions) {
		o.Timeout = timeout
	}
}

func WithStdTransport(transport http.RoundTripper) StdHTTPClientOption {
	return func(o *StdHTTPClientOptions) {
		o.Transport = transport
	}
}

func WithStdInsecureSkipVerify(skip bool) StdHTTPClientOption {
	return func(o *StdHTTPClientOptions) {
		o.InsecureSkipVerify = skip
	}
}

type StdHTTPClient struct {
	client *http.Client
}

func NewStdHTTPClient(opts ...StdHTTPClientOption) Client {
	options := &StdHTTPClientOptions{
		Timeout: DefaultTimeout,
	}

	for _, opt := range opts {
		opt(options)
	}

	client := &http.Client{
		Timeout: options.Timeout,
	}

	if options.Transport != nil {
		client.Transport = options.Transport
	} else if options.InsecureSkipVerify {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //#nosec G402
			},
		}
	}

	return &StdHTTPClient{client: client}
}

func (c *StdHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return c.client.Do(req)
}

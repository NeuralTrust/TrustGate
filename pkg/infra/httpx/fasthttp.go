package httpx

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/valyala/fasthttp"
)

type FastHTTPClient struct {
	client *fasthttp.Client
}

func NewFastHTTPClient(client *fasthttp.Client) Client {
	if client == nil {
		client = &fasthttp.Client{}
	}
	return &FastHTTPClient{
		client: client,
	}
}

func (c *FastHTTPClient) Do(req *http.Request) (*http.Response, error) {
	fastReq := fasthttp.AcquireRequest()
	fastResp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(fastReq)
	defer fasthttp.ReleaseResponse(fastResp)

	fastReq.SetRequestURI(req.URL.String())

	fastReq.Header.SetMethod(req.Method)

	for key, values := range req.Header {
		for _, value := range values {
			fastReq.Header.Add(key, value)
		}
	}

	if req.Body != nil {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		fastReq.SetBody(body)
		if err := req.Body.Close(); err != nil {
			return nil, fmt.Errorf("failed to close request body: %w", err)
		}
	}

	if req.Host != "" {
		fastReq.Header.SetHost(req.Host)
	}

	err := c.client.Do(fastReq, fastResp)
	if err != nil {
		return nil, err
	}

	resp := &http.Response{
		StatusCode: fastResp.StatusCode(),
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewReader(fastResp.Body())),
	}

	fastResp.Header.VisitAll(func(key, value []byte) {
		resp.Header.Add(string(key), string(value))
	})

	resp.Status = fastResp.Header.String()
	if i := strings.IndexByte(resp.Status, ' '); i != -1 {
		resp.Status = resp.Status[:i] + " " + http.StatusText(resp.StatusCode)
	}

	return resp, nil
}

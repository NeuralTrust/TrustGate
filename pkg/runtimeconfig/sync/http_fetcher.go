package configsync

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const (
	headerIfNoneMatch    = "If-None-Match"
	headerAuthorization  = "Authorization"
	headerInstanceID     = "X-Instance-Id"
	headerAppliedVersion = "X-Applied-Version"
	headerETag           = "ETag"
)

const maxSnapshotBytes = 256 << 20

type HTTPFetcher struct {
	url        string
	token      string
	client     *http.Client
	instanceID string
	maxBytes   int64
}

func NewHTTPFetcher(url, token string, client *http.Client, instanceID string) *HTTPFetcher {
	if client == nil {
		client = http.DefaultClient
	}
	return &HTTPFetcher{url: url, token: token, client: client, instanceID: instanceID, maxBytes: maxSnapshotBytes}
}

func (f *HTTPFetcher) Fetch(ctx context.Context, etag string) ([]byte, string, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.url, nil)
	if err != nil {
		return nil, "", false, fmt.Errorf("configsync: build snapshot request: %w", err)
	}
	if etag != "" {
		req.Header.Set(headerIfNoneMatch, etag)
		req.Header.Set(headerAppliedVersion, etag)
	}
	if f.token != "" {
		req.Header.Set(headerAuthorization, "Bearer "+f.token)
	}
	if f.instanceID != "" {
		req.Header.Set(headerInstanceID, f.instanceID)
	}

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, "", false, fmt.Errorf("configsync: fetch snapshot: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusNotModified:
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, "", true, nil
	case http.StatusOK:
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, f.maxBytes+1))
		if readErr != nil {
			return nil, "", false, fmt.Errorf("configsync: read snapshot body: %w", readErr)
		}
		if int64(len(body)) > f.maxBytes {
			return nil, "", false, fmt.Errorf("configsync: snapshot body exceeds %d bytes", f.maxBytes)
		}
		version := strings.Trim(resp.Header.Get(headerETag), `"`)
		return body, version, false, nil
	default:
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, "", false, fmt.Errorf("configsync: unexpected snapshot status %d", resp.StatusCode)
	}
}

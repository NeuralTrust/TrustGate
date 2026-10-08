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

package server

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttputil"
)

func gzipBytes(t *testing.T, p []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	require.NoError(t, err)
	_, err = zw.Write(p)
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

func deflateBytes(t *testing.T, p []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	_, err := zw.Write(p)
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

type echoPayload struct {
	Name string `json:"name"`
}

func newEncodingTestApp(t *testing.T) *fiber.App {
	t.Helper()
	app := NewBaseServer("test", ":0", config.ServerConfig{}, slog.New(slog.DiscardHandler)).Router
	echo := func(c *fiber.Ctx) error {
		var p echoPayload
		if err := c.BodyParser(&p); err != nil {
			return c.Status(fiber.StatusUnprocessableEntity).SendString(err.Error())
		}
		c.Set("X-Body-Len", strconv.Itoa(len(c.Body())))
		c.Set("X-Content-Encoding", c.Get(fiber.HeaderContentEncoding))
		c.Set("X-Content-Length", c.Get(fiber.HeaderContentLength))
		c.Set("X-Transfer-Encoding", c.Get(fiber.HeaderTransferEncoding))
		return c.SendString(p.Name)
	}
	app.Post("/echo", echo)
	app.Group("/g").All("/x", echo)
	return app
}

func doEncoded(t *testing.T, app *fiber.App, body []byte, encodings ...string) *http.Response {
	t.Helper()
	return doEncodedPath(t, app, "/echo", body, encodings...)
}

func doEncodedPath(t *testing.T, app *fiber.App, path string, body []byte, encodings ...string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
	for _, e := range encodings {
		req.Header.Add(fiber.HeaderContentEncoding, e)
	}
	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	return resp
}

func TestDecodeRequestBody(t *testing.T) {
	t.Parallel()
	payload := []byte(`{"name":"alice"}`)
	oversized := append(append([]byte(`{"name":"`), bytes.Repeat([]byte("a"), bodyLimit)...), []byte(`"}`)...)

	tests := []struct {
		name       string
		body       []byte
		encodings  []string
		wantStatus int
		wantBody   string
	}{
		{name: "plain", body: payload, wantStatus: fiber.StatusOK, wantBody: "alice"},
		{name: "identity", body: payload, encodings: []string{"identity"}, wantStatus: fiber.StatusOK, wantBody: "alice"},
		{name: "gzip", body: gzipBytes(t, payload), encodings: []string{"gzip"}, wantStatus: fiber.StatusOK, wantBody: "alice"},
		{name: "gzip mixed case", body: gzipBytes(t, payload), encodings: []string{"GZip"}, wantStatus: fiber.StatusOK, wantBody: "alice"},
		{name: "x-gzip", body: gzipBytes(t, payload), encodings: []string{"x-gzip"}, wantStatus: fiber.StatusOK, wantBody: "alice"},
		{name: "deflate", body: deflateBytes(t, payload), encodings: []string{"deflate"}, wantStatus: fiber.StatusOK, wantBody: "alice"},
		{name: "brotli", body: fasthttp.AppendBrotliBytes(nil, payload), encodings: []string{"br"}, wantStatus: fiber.StatusOK, wantBody: "alice"},
		{name: "identity on separate line", body: gzipBytes(t, payload), encodings: []string{"gzip", "identity"}, wantStatus: fiber.StatusOK, wantBody: "alice"},
		{name: "gzip with identity", body: gzipBytes(t, payload), encodings: []string{"identity, gzip"}, wantStatus: fiber.StatusOK, wantBody: "alice"},
		{name: "chained in one header", body: gzipBytes(t, gzipBytes(t, payload)), encodings: []string{"gzip, gzip"}, wantStatus: fiber.StatusUnsupportedMediaType},
		{name: "chained across headers", body: gzipBytes(t, gzipBytes(t, payload)), encodings: []string{"gzip", "gzip"}, wantStatus: fiber.StatusUnsupportedMediaType},
		{name: "unknown coding", body: payload, encodings: []string{"compress"}, wantStatus: fiber.StatusUnsupportedMediaType},
		{name: "zstd rejected", body: fasthttp.AppendZstdBytes(nil, payload), encodings: []string{"zstd"}, wantStatus: fiber.StatusUnsupportedMediaType},
		{name: "corrupt gzip", body: []byte("not gzip"), encodings: []string{"gzip"}, wantStatus: fiber.StatusBadRequest},
		{name: "gzip past body limit", body: gzipBytes(t, oversized), encodings: []string{"gzip"}, wantStatus: fiber.StatusRequestEntityTooLarge},
		{name: "deflate past body limit", body: deflateBytes(t, oversized), encodings: []string{"deflate"}, wantStatus: fiber.StatusRequestEntityTooLarge},
		{name: "brotli past body limit", body: fasthttp.AppendBrotliBytes(nil, oversized), encodings: []string{"br"}, wantStatus: fiber.StatusRequestEntityTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			resp := doEncoded(t, newEncodingTestApp(t), tt.body, tt.encodings...)
			defer func() { _ = resp.Body.Close() }()
			require.Equal(t, tt.wantStatus, resp.StatusCode)
			if tt.wantStatus != fiber.StatusOK {
				return
			}
			got, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			require.Equal(t, tt.wantBody, string(got))
			require.Equal(t, strconv.Itoa(len(payload)), resp.Header.Get("X-Body-Len"))
			require.Equal(t, strconv.Itoa(len(payload)), resp.Header.Get("X-Content-Length"))
			require.Empty(t, resp.Header.Get("X-Content-Encoding"))
			require.Empty(t, resp.Header.Get("X-Transfer-Encoding"))
		})
	}
}

func TestDecodeRequestBody_RunsBeforeEveryRoute(t *testing.T) {
	t.Parallel()
	bomb := gzipBytes(t, gzipBytes(t, []byte(`{"name":"alice"}`)))

	for _, path := range []string{"/g/x", "/does-not-exist"} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			resp := doEncodedPath(t, newEncodingTestApp(t), path, bomb, "gzip, gzip")
			defer func() { _ = resp.Body.Close() }()
			require.Equal(t, fiber.StatusUnsupportedMediaType, resp.StatusCode)
		})
	}
}

func TestDecodeRequestBody_Chunked(t *testing.T) {
	t.Parallel()
	payload := []byte(`{"name":"alice"}`)
	compressed := gzipBytes(t, payload)

	app := newEncodingTestApp(t)
	ln := fasthttputil.NewInmemoryListener()
	go func() { _ = app.Listener(ln) }()
	t.Cleanup(func() { _ = app.Shutdown() })

	conn, err := ln.Dial()
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	var raw strings.Builder
	raw.WriteString("POST /echo HTTP/1.1\r\nHost: test\r\nContent-Type: application/json\r\n")
	raw.WriteString("Content-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n")
	raw.WriteString(strconv.FormatInt(int64(len(compressed)), 16) + "\r\n" + string(compressed) + "\r\n0\r\n\r\n")
	_, err = conn.Write([]byte(raw.String()))
	require.NoError(t, err)

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, fiber.StatusOK, resp.StatusCode)
	require.Equal(t, strconv.Itoa(len(payload)), resp.Header.Get("X-Content-Length"))
	require.Empty(t, resp.Header.Get("X-Transfer-Encoding"))
}

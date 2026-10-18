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

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

func TestComposer_Invoke_Zoom4741IsAToolError(t *testing.T) {
	t.Parallel()
	const leaked = "secret-token-body"
	reg := zoomRegistry(t)
	rawUpstream := `{"content":[{"type":"text","text":"{\"code\":4741,\"message\":\"` + leaked + `\"}"}],"isError":true}`
	up := &fakeUpstream{result: json.RawMessage(rawUpstream)}
	res, err := invokeZoom(t, reg, up)
	if err != nil {
		t.Fatalf("4741 must be a tool result, not an error: %v", err)
	}
	assertZoomRevokedToolError(t, res, leaked)
}

func TestComposer_Invoke_Zoom4741ErrorIsAToolError(t *testing.T) {
	t.Parallel()
	const leaked = "secret-token-body"
	reg := zoomRegistry(t)
	up := &fakeUpstream{callErr: errors.New(`{"code":4741,"message":"` + leaked + `"}`)}
	res, err := invokeZoom(t, reg, up)
	if err != nil {
		t.Fatalf("4741 error must be a tool result, not an error: %v", err)
	}
	assertZoomRevokedToolError(t, res, leaked)
}

func TestComposer_Invoke_Zoom4741ContentWithoutIsErrorIsAToolError(t *testing.T) {
	t.Parallel()
	const leaked = "secret-token-body"
	reg := zoomRegistry(t)
	up := &fakeUpstream{result: json.RawMessage(`{"content":[{"type":"text","text":"{\"code\":4741,\"message\":\"` + leaked + `\"}"}]}`)}
	res, err := invokeZoom(t, reg, up)
	if err != nil {
		t.Fatalf("4741 body must be a tool result, not an error: %v", err)
	}
	assertZoomRevokedToolError(t, res, leaked)
}

func TestComposer_Invoke_OtherZoomErrorsStay(t *testing.T) {
	t.Parallel()
	reg := zoomRegistry(t)
	raw := `{"content":[{"type":"text","text":"{\"code\":124,\"message\":\"invalid token\"}"}],"isError":true}`
	up := &fakeUpstream{result: json.RawMessage(raw)}
	res, err := invokeZoom(t, reg, up)
	if err != nil {
		t.Fatalf("other zoom error: %v", err)
	}
	if string(res) != raw {
		t.Fatalf("result = %s, want the upstream error left as it arrived", res)
	}
}

func TestComposer_Invoke_Zoom47410IsNot4741(t *testing.T) {
	t.Parallel()
	reg := zoomRegistry(t)
	raw := `{"content":[{"type":"text","text":"{\"code\":47410,\"message\":\"other\"}"}],"isError":true}`
	up := &fakeUpstream{result: json.RawMessage(raw)}
	res, err := invokeZoom(t, reg, up)
	if err != nil {
		t.Fatalf("47410: %v", err)
	}
	if string(res) != raw {
		t.Fatalf("result = %s, want 47410 left alone", res)
	}
}

func TestComposer_Invoke_NonZoom4741Stays(t *testing.T) {
	t.Parallel()
	reg := mcpRegistry(t, "github", "https://a.example.com/mcp")
	raw := `{"content":[{"type":"text","text":"{\"code\":4741,\"message\":\"nope\"}"}],"isError":true}`
	up := &fakeUpstream{result: json.RawMessage(raw)}
	res, err := invokeZoom(t, reg, up)
	if err != nil {
		t.Fatalf("non-zoom: %v", err)
	}
	if string(res) != raw {
		t.Fatalf("result = %s, want a non-zoom 4741 left alone", res)
	}
}

func TestComposer_Invoke_ZoomSuccess4741InAStringStays(t *testing.T) {
	t.Parallel()
	reg := zoomRegistry(t)
	raw := `{"content":[{"type":"text","text":"{\"topic\":\"weekly sync \\\"code\\\": 4741\"}"}]}`
	up := &fakeUpstream{result: json.RawMessage(raw)}
	res, err := invokeZoom(t, reg, up)
	if err != nil {
		t.Fatalf("success: %v", err)
	}
	if string(res) != raw {
		t.Fatalf("result = %s, want a topic that quotes code 4741 left alone", res)
	}
}

func TestComposer_Invoke_ZoomSuccessNested4741Stays(t *testing.T) {
	t.Parallel()
	reg := zoomRegistry(t)
	raw := `{"content":[{"type":"text","text":"{\"meeting\":{\"code\":4741,\"message\":\"room\"}}"}]}`
	up := &fakeUpstream{result: json.RawMessage(raw)}
	res, err := invokeZoom(t, reg, up)
	if err != nil {
		t.Fatalf("success: %v", err)
	}
	if string(res) != raw {
		t.Fatalf("result = %s, want a nested 4741 left alone", res)
	}
}

func TestComposer_Invoke_ZoomSuccessStringCode4741Stays(t *testing.T) {
	t.Parallel()
	reg := zoomRegistry(t)
	raw := `{"content":[{"type":"text","text":"{\"code\":\"4741\",\"message\":\"room\"}"}]}`
	up := &fakeUpstream{result: json.RawMessage(raw)}
	res, err := invokeZoom(t, reg, up)
	if err != nil {
		t.Fatalf("success: %v", err)
	}
	if string(res) != raw {
		t.Fatalf("result = %s, want a string code left alone", res)
	}
}

func TestComposer_Invoke_Zoom4741InsideAnErrorStringStays(t *testing.T) {
	t.Parallel()
	reg := zoomRegistry(t)
	up := &fakeUpstream{callErr: errors.New(`zoom upstream {"code":4741,"message":"secret-token-body"}`)}
	_, err := invokeZoom(t, reg, up)
	if err == nil || strings.Contains(err.Error(), zoomRevokedConnectionText) {
		t.Fatalf("error = %v, want the original error, not the reconnect tool error", err)
	}
}

func TestComposer_Invoke_ZoomSuccessMentioning4741Stays(t *testing.T) {
	t.Parallel()
	reg := zoomRegistry(t)
	raw := `{"content":[{"type":"text","text":"meeting room 4741 is ready"}]}`
	up := &fakeUpstream{result: json.RawMessage(raw)}
	res, err := invokeZoom(t, reg, up)
	if err != nil {
		t.Fatalf("success: %v", err)
	}
	if string(res) != raw {
		t.Fatalf("result = %s, want a successful mention left alone", res)
	}
}

func TestComposer_Invoke_ZoomUnauthorizedWithout4741StaysAnError(t *testing.T) {
	t.Parallel()
	reg := zoomRegistry(t)
	up := &fakeUpstream{callErr: ErrUpstreamUnauthorized}
	_, err := invokeZoom(t, reg, up)
	if !errors.Is(err, ErrUpstreamUnauthorized) {
		t.Fatalf("error = %v, want ErrUpstreamUnauthorized unchanged", err)
	}
}

func zoomRegistry(t *testing.T) *registrydomain.Registry {
	t.Helper()
	reg := mcpRegistry(t, "zoom-docs", "https://mcp.zoom.us/mcp/docs/streamable")
	reg.MCPTarget.Code = "us.zoom/docs"
	return reg
}

func invokeZoom(t *testing.T, reg *registrydomain.Registry, up *fakeUpstream) (json.RawMessage, error) {
	t.Helper()
	dialer := &fakeDialer{upstreams: map[string]*fakeUpstream{reg.MCPTarget.URL: up}}
	c := newTestComposer(dialer)
	rc := routable(&consumerdomain.Consumer{Type: consumerdomain.TypeMCP}, reg)
	return c.Invoke(context.Background(), rc, &ResolvedTool{
		Registry: reg,
		Tool:     Tool{Name: "create_file_with_content"},
		Exposed:  "zoom_docs_create_file_with_content",
	}, json.RawMessage(`{}`))
}

func assertZoomRevokedToolError(t *testing.T, res json.RawMessage, leaked string) {
	t.Helper()
	var out struct {
		IsError bool `json:"isError"`
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(res, &out); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if !out.IsError || len(out.Content) != 1 || out.Content[0].Text != zoomRevokedConnectionText {
		t.Fatalf("result = %s, want the zoom revoked tool error", res)
	}
	if strings.Contains(string(res), leaked) || strings.Contains(string(res), "4741") {
		t.Fatalf("rewritten result still carries the upstream error: %s", res)
	}
}

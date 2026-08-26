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

package openapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	appopenapi "github.com/NeuralTrust/TrustGate/pkg/app/openapi"
	infraopenapi "github.com/NeuralTrust/TrustGate/pkg/infra/openapi"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"golang.org/x/sync/singleflight"
)

const maxResponseBytes = 10 << 20

type Dialer struct {
	remote   appmcp.Dialer
	compiler appopenapi.Compiler
	cache    sync.Map
	flight   singleflight.Group
	client   *http.Client
}

type compiledDocument struct {
	document   *appopenapi.Document
	operations map[string]appopenapi.Operation
	validators map[string]*jsonschema.Schema
	tools      []appmcp.Tool
}

func NewDialer(remote appmcp.Dialer, compiler appopenapi.Compiler) appmcp.Dialer {
	return NewDialerWithClient(remote, compiler, infraopenapi.NewSafeHTTPClient(30*time.Second))
}

// NewDialerWithClient returns a multiplexing dialer using the supplied REST client.
func NewDialerWithClient(
	remote appmcp.Dialer,
	compiler appopenapi.Compiler,
	client *http.Client,
) appmcp.Dialer {
	return &Dialer{
		remote:   remote,
		compiler: compiler,
		client:   client,
	}
}

func (d *Dialer) Connect(ctx context.Context, target appmcp.Target) (appmcp.Upstream, error) {
	if target.OpenAPI == nil {
		return d.remote.Connect(ctx, target)
	}
	key := target.Revision
	if key == "" {
		key = target.OpenAPI.SpecURL + "|" + target.OpenAPI.BaseURL
	} else {
		d.evictStaleRevisions(key)
	}
	compiled, err := d.load(ctx, key, *target.OpenAPI)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", appmcp.ErrUnreachable, err)
	}
	return &upstream{
		compiled: compiled,
		headers:  target.Headers,
		client:   d.client,
	}, nil
}

func (d *Dialer) evictStaleRevisions(current string) {
	separator := strings.IndexByte(current, ':')
	if separator < 0 {
		return
	}
	prefix := current[:separator+1]
	d.cache.Range(func(key, _ any) bool {
		cachedKey, ok := key.(string)
		if ok && cachedKey != current && strings.HasPrefix(cachedKey, prefix) {
			d.cache.Delete(cachedKey)
		}
		return true
	})
}

func (d *Dialer) load(ctx context.Context, key string, source appopenapi.Source) (*compiledDocument, error) {
	if cached, ok := d.cache.Load(key); ok {
		return cached.(*compiledDocument), nil
	}
	value, err, _ := d.flight.Do(key, func() (any, error) {
		if cached, ok := d.cache.Load(key); ok {
			return cached.(*compiledDocument), nil
		}
		document, err := d.compiler.Compile(ctx, source)
		if err != nil {
			return nil, err
		}
		compiled, err := prepare(document)
		if err != nil {
			return nil, err
		}
		d.cache.Store(key, compiled)
		return compiled, nil
	})
	if err != nil {
		return nil, err
	}
	return value.(*compiledDocument), nil
}

func prepare(document *appopenapi.Document) (*compiledDocument, error) {
	out := &compiledDocument{
		document:   document,
		operations: make(map[string]appopenapi.Operation, len(document.Operations)),
		validators: make(map[string]*jsonschema.Schema, len(document.Operations)),
		tools:      make([]appmcp.Tool, 0, len(document.Operations)),
	}
	for i, operation := range document.Operations {
		out.operations[operation.Name] = operation
		validator, err := compileValidator(i, operation.InputSchema)
		if err != nil {
			return nil, fmt.Errorf("compile validator for %q: %w", operation.Name, err)
		}
		out.validators[operation.Name] = validator
		payload := map[string]any{
			"name":        operation.Name,
			"description": operation.Description,
			"inputSchema": json.RawMessage(operation.InputSchema),
		}
		data, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		var tool appmcp.Tool
		if err := json.Unmarshal(data, &tool); err != nil {
			return nil, err
		}
		out.tools = append(out.tools, tool)
	}
	return out, nil
}

func compileValidator(index int, raw json.RawMessage) (*jsonschema.Schema, error) {
	var schema any
	if err := json.Unmarshal(raw, &schema); err != nil {
		return nil, err
	}
	location := fmt.Sprintf("urn:trustgate:openapi:operation:%d", index)
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	if err := compiler.AddResource(location, schema); err != nil {
		return nil, err
	}
	return compiler.Compile(location)
}

type upstream struct {
	compiled *compiledDocument
	headers  map[string]string
	client   *http.Client
}

func (u *upstream) ListTools(context.Context) ([]appmcp.Tool, error) {
	return append([]appmcp.Tool(nil), u.compiled.tools...), nil
}

func (u *upstream) CallTool(ctx context.Context, name string, arguments json.RawMessage) (json.RawMessage, error) {
	operation, ok := u.compiled.operations[name]
	if !ok {
		return nil, fmt.Errorf("%w: %s", appmcp.ErrToolNotFound, name)
	}
	var args map[string]any
	if len(arguments) == 0 {
		args = map[string]any{}
	} else if err := json.Unmarshal(arguments, &args); err != nil {
		return nil, &appmcp.RPCError{Code: -32602, Message: "invalid tool arguments"}
	}
	if err := u.compiled.validators[name].Validate(args); err != nil {
		return nil, &appmcp.RPCError{Code: -32602, Message: fmt.Sprintf("invalid tool arguments: %v", err)}
	}
	req, err := u.request(ctx, operation, args)
	if err != nil {
		return nil, &appmcp.RPCError{Code: -32602, Message: err.Error()}
	}
	res, err := u.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", appmcp.ErrUnreachable, err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("openapi upstream: read response: %w", err)
	}
	if len(body) > maxResponseBytes {
		return nil, errors.New("openapi upstream response exceeds size limit")
	}
	return toolResult(res.StatusCode, res.Header.Get("Content-Type"), body)
}

func (u *upstream) request(
	ctx context.Context,
	operation appopenapi.Operation,
	args map[string]any,
) (*http.Request, error) {
	path := operation.Path
	query := make(url.Values)
	headers := make(http.Header)
	for _, parameter := range operation.Parameters {
		value, present := args[parameter.Name]
		if !present || value == nil {
			continue
		}
		switch parameter.In {
		case "path":
			path = strings.ReplaceAll(path, "{"+parameter.Name+"}", url.PathEscape(fmt.Sprint(value)))
		case "query":
			addQuery(query, parameter.Name, value, parameter.Explode)
		case "header":
			headers.Set(parameter.Name, fmt.Sprint(value))
		case "cookie":
			return nil, fmt.Errorf("cookie parameter %q is not supported", parameter.Name)
		default:
			return nil, fmt.Errorf("parameter %q has unsupported location %q", parameter.Name, parameter.In)
		}
	}
	var requestBody io.Reader
	if len(operation.BodyFields) > 0 {
		body := make(map[string]any)
		for _, field := range operation.BodyFields {
			if value, ok := args[field]; ok {
				body[field] = value
			}
		}
		data, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		requestBody = bytes.NewReader(data)
		headers.Set("Content-Type", "application/json")
	} else if operation.BodyArgument != "" {
		data, err := json.Marshal(args[operation.BodyArgument])
		if err != nil {
			return nil, err
		}
		requestBody = bytes.NewReader(data)
		headers.Set("Content-Type", "application/json")
	}
	rawURL := strings.TrimRight(u.compiled.document.BaseURL, "/") + "/" + strings.TrimLeft(path, "/")
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("build upstream URL: %w", err)
	}
	parsed.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, operation.Method, parsed.String(), requestBody)
	if err != nil {
		return nil, err
	}
	req.Header = headers
	for key, value := range u.headers {
		req.Header.Set(key, value)
	}
	return req, nil
}

func (u *upstream) ListResources(context.Context) ([]appmcp.Resource, error) {
	return nil, nil
}

func (u *upstream) ListResourceTemplates(context.Context) ([]appmcp.ResourceTemplate, error) {
	return nil, nil
}

func (u *upstream) ReadResource(context.Context, string) (json.RawMessage, error) {
	return nil, appmcp.ErrNotSupported
}

func (u *upstream) ListPrompts(context.Context) ([]appmcp.Prompt, error) {
	return nil, nil
}

func (u *upstream) GetPrompt(context.Context, string, map[string]string) (json.RawMessage, error) {
	return nil, appmcp.ErrNotSupported
}

func (u *upstream) SupportsResources() bool {
	return false
}

func (u *upstream) SupportsPrompts() bool {
	return false
}

func (u *upstream) Close(context.Context) {
}

func addQuery(query url.Values, name string, value any, explode bool) {
	items, ok := value.([]any)
	if !ok {
		query.Set(name, fmt.Sprint(value))
		return
	}
	if explode {
		for _, item := range items {
			query.Add(name, fmt.Sprint(item))
		}
		return
	}
	values := make([]string, 0, len(items))
	for _, item := range items {
		values = append(values, fmt.Sprint(item))
	}
	query.Set(name, strings.Join(values, ","))
}

func toolResult(status int, contentType string, body []byte) (json.RawMessage, error) {
	text := string(body)
	if text == "" {
		text = http.StatusText(status)
	}
	result := map[string]any{
		"content": []map[string]any{{"type": "text", "text": text}},
		"isError": status < 200 || status >= 300,
	}
	if strings.Contains(strings.ToLower(contentType), "json") && len(body) > 0 {
		var structured any
		if json.Unmarshal(body, &structured) == nil {
			result["structuredContent"] = structured
		}
	}
	data, err := json.Marshal(result)
	return data, err
}

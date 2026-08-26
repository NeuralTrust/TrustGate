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
	"sort"
	"strings"
	"sync"
	"time"

	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	appopenapi "github.com/NeuralTrust/TrustGate/pkg/app/openapi"
	infraopenapi "github.com/NeuralTrust/TrustGate/pkg/infra/openapi"
	"github.com/getkin/kin-openapi/openapi3"
	"golang.org/x/sync/singleflight"
)

const (
	maxResponseBytes = 10 << 20
	compileCacheTTL  = 5 * time.Minute
	maxCacheEntries  = 256
)

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
	validators map[string]*openapi3.Schema
	tools      []appmcp.Tool
}

type cacheEntry struct {
	compiled  *compiledDocument
	expiresAt time.Time
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
	if cached, ok := d.cached(key); ok {
		return cached, nil
	}
	value, err, _ := d.flight.Do(key, func() (any, error) {
		if cached, ok := d.cached(key); ok {
			return cached, nil
		}
		document, err := d.compiler.Compile(ctx, source)
		if err != nil {
			return nil, err
		}
		compiled, err := prepare(document)
		if err != nil {
			return nil, err
		}
		d.pruneCache()
		d.cache.Store(key, cacheEntry{compiled: compiled, expiresAt: time.Now().Add(compileCacheTTL)})
		return compiled, nil
	})
	if err != nil {
		return nil, err
	}
	return value.(*compiledDocument), nil
}

func (d *Dialer) cached(key string) (*compiledDocument, bool) {
	value, ok := d.cache.Load(key)
	if !ok {
		return nil, false
	}
	entry := value.(cacheEntry)
	if time.Now().After(entry.expiresAt) {
		d.cache.Delete(key)
		return nil, false
	}
	return entry.compiled, true
}

func (d *Dialer) pruneCache() {
	now := time.Now()
	count := 0
	var oldestKey string
	var oldest time.Time
	d.cache.Range(func(key, value any) bool {
		entry := value.(cacheEntry)
		if now.After(entry.expiresAt) {
			d.cache.Delete(key)
			return true
		}
		count++
		if oldestKey == "" || entry.expiresAt.Before(oldest) {
			oldestKey = key.(string)
			oldest = entry.expiresAt
		}
		return true
	})
	if count >= maxCacheEntries && oldestKey != "" {
		d.cache.Delete(oldestKey)
	}
}

func prepare(document *appopenapi.Document) (*compiledDocument, error) {
	out := &compiledDocument{
		document:   document,
		operations: make(map[string]appopenapi.Operation, len(document.Operations)),
		validators: make(map[string]*openapi3.Schema, len(document.Operations)),
		tools:      make([]appmcp.Tool, 0, len(document.Operations)),
	}
	for _, operation := range document.Operations {
		out.operations[operation.Name] = operation
		validator, err := compileValidator(operation.InputSchema)
		if err != nil {
			return nil, fmt.Errorf("compile validator for %q: %w", operation.Name, err)
		}
		out.validators[operation.Name] = validator
		payload := map[string]any{
			"name":        operation.Name,
			"description": operation.Description,
			"inputSchema": json.RawMessage(operation.InputSchema),
		}
		if len(operation.OutputSchema) > 0 {
			payload["outputSchema"] = json.RawMessage(operation.OutputSchema)
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

func compileValidator(raw json.RawMessage) (*openapi3.Schema, error) {
	var schema openapi3.Schema
	if err := json.Unmarshal(raw, &schema); err != nil {
		return nil, err
	}
	return &schema, nil
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
	validationOptions := []openapi3.SchemaValidationOption{}
	if strings.HasPrefix(u.compiled.document.Version, "3.1") ||
		strings.HasPrefix(u.compiled.document.Version, "3.2") {
		validationOptions = append(validationOptions, openapi3.EnableJSONSchema2020())
	}
	if err := u.compiled.validators[name].VisitJSON(args, validationOptions...); err != nil {
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
	cookies := make(map[string]string)
	for _, parameter := range operation.Parameters {
		value, present := args[parameter.Name]
		if !present || value == nil {
			continue
		}
		switch parameter.In {
		case "path":
			path = strings.ReplaceAll(
				path,
				"{"+parameter.Name+"}",
				url.PathEscape(serializeSimple(value, parameter.Explode)),
			)
		case "query":
			addQuery(query, parameter.Name, value, parameter.Style, parameter.Explode)
		case "header":
			headers.Set(parameter.Name, serializeSimple(value, parameter.Explode))
		case "cookie":
			cookies[parameter.Name] = serializeSimple(value, parameter.Explode)
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
	for name, value := range cookies {
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}
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

func addQuery(query url.Values, name string, value any, style string, explode bool) {
	if object, ok := value.(map[string]any); ok {
		keys := sortedMapKeys(object)
		if style == "deepObject" {
			for _, key := range keys {
				query.Set(name+"["+key+"]", fmt.Sprint(object[key]))
			}
			return
		}
		if explode {
			for _, key := range keys {
				query.Set(key, fmt.Sprint(object[key]))
			}
			return
		}
		query.Set(name, serializeSimple(object, false))
		return
	}
	items, ok := value.([]any)
	if !ok {
		query.Set(name, fmt.Sprint(value))
		return
	}
	switch style {
	case "spaceDelimited":
		query.Set(name, joinValues(items, " "))
	case "pipeDelimited":
		query.Set(name, joinValues(items, "|"))
	default:
		if explode {
			for _, item := range items {
				query.Add(name, fmt.Sprint(item))
			}
			return
		}
		query.Set(name, joinValues(items, ","))
	}
}

func serializeSimple(value any, explode bool) string {
	if items, ok := value.([]any); ok {
		return joinValues(items, ",")
	}
	if object, ok := value.(map[string]any); ok {
		keys := sortedMapKeys(object)
		values := make([]string, 0, len(keys))
		for _, key := range keys {
			if explode {
				values = append(values, key+"="+fmt.Sprint(object[key]))
			} else {
				values = append(values, key, fmt.Sprint(object[key]))
			}
		}
		return strings.Join(values, ",")
	}
	return fmt.Sprint(value)
}

func joinValues(items []any, separator string) string {
	values := make([]string, 0, len(items))
	for _, item := range items {
		values = append(values, fmt.Sprint(item))
	}
	return strings.Join(values, separator)
}

func sortedMapKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
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
		var structured map[string]any
		if json.Unmarshal(body, &structured) == nil {
			result["structuredContent"] = structured
		}
	}
	data, err := json.Marshal(result)
	return data, err
}

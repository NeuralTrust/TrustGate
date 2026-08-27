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
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	appopenapi "github.com/NeuralTrust/TrustGate/pkg/app/openapi"
	"github.com/getkin/kin-openapi/openapi3"
)

const (
	maxSpecBytes          = 5 << 20
	maxToolName           = 64
	maxCompiledOperations = 500
	maxListedSkips        = 5
)

var invalidToolName = regexp.MustCompile(`[^a-zA-Z0-9_-]+`)

// blockedNetworkPrefixes are destinations that are never safe to dial, even
// via a public DNS name (documentation, benchmarking, and reserved ranges).
// RFC1918 and CGNAT (100.64/10) are not listed: cluster-internal names such as
// agentgateway-admin.dev.neuraltrust.ai often resolve to those ranges.
var blockedNetworkPrefixes = []netip.Prefix{
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001:db8::/32"),
}

var cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")

type unsupportedOperationError struct {
	reason string
}

func (e *unsupportedOperationError) Error() string {
	return e.reason
}

type Compiler struct {
	client               *http.Client
	validateDestinations bool
}

func NewCompiler() appopenapi.Compiler {
	return &Compiler{
		client:               NewSafeHTTPClient(10 * time.Second),
		validateDestinations: true,
	}
}

// NewCompilerWithClient returns a compiler using the supplied HTTP client.
func NewCompilerWithClient(client *http.Client) appopenapi.Compiler {
	return &Compiler{client: client}
}

func (c *Compiler) Compile(ctx context.Context, source appopenapi.Source) (*appopenapi.Document, error) {
	location, err := url.Parse(source.SpecURL)
	if err != nil || (location.Scheme != "http" && location.Scheme != "https") || location.Host == "" {
		return nil, compileError(appopenapi.StageFetch, errors.New("spec_url must be a valid http(s) URL"))
	}
	data, err := c.fetch(ctx, location.String())
	if err != nil {
		return nil, compileError(appopenapi.StageFetch, err)
	}
	loader := openapi3.NewLoader()
	loader.Context = ctx
	loader.IsExternalRefsAllowed = false
	doc, err := loader.LoadFromDataWithPath(data, location)
	if err != nil {
		return nil, compileError(appopenapi.StageParse, err)
	}
	if err := doc.Validate(ctx); err != nil {
		return nil, compileError(appopenapi.StageParse, err)
	}
	baseURL, err := resolveBaseURL(source.BaseURL, doc.Servers, location)
	if err != nil {
		return nil, compileError(appopenapi.StageCompile, err)
	}
	if c.validateDestinations {
		if err := validatePublicURL(ctx, baseURL); err != nil {
			return nil, compileError(appopenapi.StageCompile, fmt.Errorf("base_url: %w", err))
		}
	}
	operations, warnings, err := compileOperations(doc)
	if err != nil {
		return nil, compileError(appopenapi.StageCompile, err)
	}
	if len(operations) == 0 {
		return nil, compileError(appopenapi.StageCompile, errors.New("the document has no callable operations"))
	}
	if len(operations) > 80 {
		warnings = append(warnings, appopenapi.Warning{
			Code:    "large_toolset",
			Message: fmt.Sprintf("the document exposes %d tools; curate the toolset to limit client context usage", len(operations)),
		})
	}
	title := ""
	if doc.Info != nil {
		title = doc.Info.Title
	}
	return &appopenapi.Document{
		Version:    doc.OpenAPI,
		Title:      title,
		BaseURL:    baseURL,
		Operations: operations,
		Warnings:   warnings,
	}, nil
}

func (c *Compiler) fetch(ctx context.Context, rawURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json, application/yaml, text/yaml, */*")
	req.Header.Set("User-Agent", "TrustGate-OpenAPI/1.0")
	res, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch document: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, fmt.Errorf("fetch document: upstream returned %s", res.Status)
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, maxSpecBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read document: %w", err)
	}
	if len(data) > maxSpecBytes {
		return nil, fmt.Errorf("document exceeds %d bytes", maxSpecBytes)
	}
	return data, nil
}

func compileOperations(doc *openapi3.T) ([]appopenapi.Operation, []appopenapi.Warning, error) {
	paths := doc.Paths.InMatchingOrder()
	operationCount := 0
	for _, path := range paths {
		operationCount += len(doc.Paths.Value(path).Operations())
	}
	if operationCount > maxCompiledOperations {
		return nil, nil, fmt.Errorf(
			"the document declares %d operations; the maximum supported is %d",
			operationCount,
			maxCompiledOperations,
		)
	}
	var operations []appopenapi.Operation
	var skipped []string
	syntheticCount := 0
	syntheticExample := ""
	taken := make(map[string]int)
	for _, path := range paths {
		item := doc.Paths.Value(path)
		methods := make([]string, 0, len(item.Operations()))
		for method := range item.Operations() {
			methods = append(methods, method)
		}
		sort.Strings(methods)
		for _, method := range methods {
			op := item.GetOperation(method)
			name, synthetic := operationName(method, path, op.OperationID)
			if synthetic {
				syntheticCount++
				if syntheticExample == "" {
					syntheticExample = name
				}
			}
			taken[name]++
			if taken[name] > 1 {
				suffix := fmt.Sprintf("_%d", taken[name])
				name = strings.TrimRight(name[:min(len(name), maxToolName-len(suffix))], "_") + suffix
			}
			compiled, err := compileOperation(name, strings.ToUpper(method), path, item.Parameters, op)
			if err != nil {
				var unsupported *unsupportedOperationError
				if errors.As(err, &unsupported) {
					skipped = append(skipped, fmt.Sprintf("%s %s (%s)", strings.ToUpper(method), path, unsupported.reason))
					continue
				}
				return nil, nil, fmt.Errorf("%s %s: %w", strings.ToUpper(method), path, err)
			}
			operations = append(operations, compiled)
		}
	}
	return operations, summarize(syntheticCount, syntheticExample, skipped), nil
}

// summarize folds per-operation findings into one warning each. A document
// without operationIds would otherwise emit a warning per operation and bury
// the tool preview.
func summarize(syntheticCount int, syntheticExample string, skipped []string) []appopenapi.Warning {
	var warnings []appopenapi.Warning
	if syntheticCount > 0 {
		warnings = append(warnings, appopenapi.Warning{
			Code: "synthetic_tool_name",
			Message: fmt.Sprintf(
				"%s without operationId; tool names come from the method and path (e.g. %q)",
				pluralize(syntheticCount, "operation"),
				syntheticExample,
			),
		})
	}
	if len(skipped) > 0 {
		listed := skipped
		suffix := ""
		if len(listed) > maxListedSkips {
			suffix = fmt.Sprintf(" and %d more", len(listed)-maxListedSkips)
			listed = listed[:maxListedSkips]
		}
		warnings = append(warnings, appopenapi.Warning{
			Code: "unsupported_operation",
			Message: fmt.Sprintf(
				"%s skipped: %s%s",
				pluralize(len(skipped), "operation"),
				strings.Join(listed, "; "),
				suffix,
			),
		})
	}
	return warnings
}

func pluralize(count int, noun string) string {
	if count == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", count, noun)
}

func compileOperation(
	name string,
	method string,
	path string,
	pathParams openapi3.Parameters,
	op *openapi3.Operation,
) (appopenapi.Operation, error) {
	properties := make(map[string]any)
	required := make([]string, 0)
	parameters := mergeParameters(pathParams, op.Parameters)
	compiledParams := make([]appopenapi.Parameter, 0, len(parameters))
	for _, ref := range parameters {
		if ref == nil || ref.Value == nil {
			continue
		}
		param := ref.Value
		schema := map[string]any{}
		if param.Schema != nil && param.Schema.Value != nil {
			var err error
			schema, err = schemaMap(param.Schema)
			if err != nil {
				return appopenapi.Operation{}, fmt.Errorf("parameter %q: %w", param.Name, err)
			}
		}
		if param.Description != "" {
			schema["description"] = param.Description
		}
		properties[param.Name] = schema
		if param.Required {
			required = append(required, param.Name)
		}
		explode := param.In == openapi3.ParameterInQuery
		if param.Explode != nil {
			explode = *param.Explode
		}
		style, err := parameterStyle(param.In, param.Style)
		if err != nil {
			return appopenapi.Operation{}, &unsupportedOperationError{reason: fmt.Sprintf("parameter %q: %v", param.Name, err)}
		}
		compiledParams = append(compiledParams, appopenapi.Parameter{
			Name:     param.Name,
			In:       param.In,
			Required: param.Required,
			Style:    style,
			Explode:  explode,
		})
	}
	bodyFields, bodyArgument, err := compileRequestBody(op.RequestBody, properties, &required)
	if err != nil {
		return appopenapi.Operation{}, err
	}
	input := map[string]any{
		"type":                 "object",
		"properties":           properties,
		"additionalProperties": false,
	}
	if len(required) > 0 {
		input["required"] = uniqueStrings(required)
	}
	raw, err := json.Marshal(input)
	if err != nil {
		return appopenapi.Operation{}, fmt.Errorf("marshal input schema: %w", err)
	}
	outputSchema, err := compileOutputSchema(op.Responses)
	if err != nil {
		return appopenapi.Operation{}, err
	}
	description := strings.TrimSpace(strings.Join([]string{op.Summary, op.Description}, "\n\n"))
	if description == "" {
		description = method + " " + path
	}
	return appopenapi.Operation{
		Name:         name,
		Description:  description,
		Method:       method,
		Path:         path,
		InputSchema:  raw,
		OutputSchema: outputSchema,
		Parameters:   compiledParams,
		BodyFields:   bodyFields,
		BodyArgument: bodyArgument,
	}, nil
}

func parameterStyle(location, style string) (string, error) {
	if style == "" {
		switch location {
		case "query", "cookie":
			style = "form"
		case "path", "header":
			style = "simple"
		}
	}
	supported := map[string]map[string]struct{}{
		"query":  {"form": {}, "spaceDelimited": {}, "pipeDelimited": {}, "deepObject": {}},
		"path":   {"simple": {}},
		"header": {"simple": {}},
		"cookie": {"form": {}},
	}
	styles, ok := supported[location]
	if !ok {
		return "", fmt.Errorf("unsupported parameter location %q", location)
	}
	if _, ok := styles[style]; !ok {
		return "", fmt.Errorf("unsupported %s style %q", location, style)
	}
	return style, nil
}

func compileOutputSchema(responses *openapi3.Responses) (json.RawMessage, error) {
	if responses == nil {
		return nil, nil
	}
	keys := responses.Keys()
	sort.Strings(keys)
	for _, status := range keys {
		if !strings.HasPrefix(status, "2") {
			continue
		}
		response := responses.Value(status)
		if response == nil || response.Value == nil {
			continue
		}
		media := response.Value.Content.Get("application/json")
		if media == nil || media.Schema == nil || media.Schema.Value == nil {
			continue
		}
		schema, err := schemaMap(media.Schema)
		if err != nil {
			return nil, fmt.Errorf("response %s: %w", status, err)
		}
		return json.Marshal(schema)
	}
	return nil, nil
}

func compileRequestBody(
	ref *openapi3.RequestBodyRef,
	properties map[string]any,
	required *[]string,
) ([]string, string, error) {
	if ref == nil || ref.Value == nil {
		return nil, "", nil
	}
	media := ref.Value.Content.Get("application/json")
	if media == nil || media.Schema == nil || media.Schema.Value == nil {
		return nil, "", &unsupportedOperationError{reason: "only application/json request bodies are supported"}
	}
	bodySchema, err := schemaMap(media.Schema)
	if err != nil {
		return nil, "", fmt.Errorf("request body: %w", err)
	}
	bodyProperties, ok := bodySchema["properties"].(map[string]any)
	if ok && len(bodyProperties) > 0 {
		for field := range bodyProperties {
			if _, collision := properties[field]; collision {
				return compileNestedBody(ref, bodySchema, properties, required)
			}
		}
		fields := make([]string, 0, len(bodyProperties))
		for field, schema := range bodyProperties {
			properties[field] = schema
			fields = append(fields, field)
		}
		sort.Strings(fields)
		*required = append(*required, stringSlice(bodySchema["required"])...)
		return fields, "", nil
	}
	return compileNestedBody(ref, bodySchema, properties, required)
}

func compileNestedBody(
	ref *openapi3.RequestBodyRef,
	bodySchema map[string]any,
	properties map[string]any,
	required *[]string,
) ([]string, string, error) {
	argument := "body"
	if _, collision := properties[argument]; collision {
		argument = "requestBody"
	}
	properties[argument] = bodySchema
	if ref.Value.Required {
		*required = append(*required, argument)
	}
	return nil, argument, nil
}

func mergeParameters(pathParams, operationParams openapi3.Parameters) openapi3.Parameters {
	merged := make(map[string]*openapi3.ParameterRef)
	for _, ref := range append(pathParams, operationParams...) {
		if ref == nil || ref.Value == nil {
			continue
		}
		merged[ref.Value.In+":"+ref.Value.Name] = ref
	}
	keys := make([]string, 0, len(merged))
	for key := range merged {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make(openapi3.Parameters, 0, len(keys))
	for _, key := range keys {
		out = append(out, merged[key])
	}
	return out
}

func schemaMap(ref *openapi3.SchemaRef) (map[string]any, error) {
	if ref == nil || ref.Value == nil {
		return map[string]any{}, nil
	}
	data, err := json.Marshal(ref.Value)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func operationName(method, path, operationID string) (string, bool) {
	name := strings.TrimSpace(operationID)
	synthetic := name == ""
	if synthetic {
		name = strings.ToLower(method) + "_" + strings.ReplaceAll(strings.Trim(path, "/"), "-", "_")
	}
	name = invalidToolName.ReplaceAllString(name, "_")
	name = strings.Trim(name, "_")
	if name == "" {
		name = strings.ToLower(method) + "_operation"
	}
	if len(name) > maxToolName {
		sum := sha256.Sum256([]byte(name))
		suffix := fmt.Sprintf("_%x", sum[:4])
		name = strings.TrimRight(name[:maxToolName-len(suffix)], "_") + suffix
	}
	return name, synthetic
}

func resolveBaseURL(override string, servers openapi3.Servers, location *url.URL) (string, error) {
	raw := strings.TrimSpace(override)
	if raw == "" && len(servers) > 0 && servers[0] != nil {
		server := servers[0]
		raw = strings.TrimSpace(server.URL)
		for name, variable := range server.Variables {
			if variable == nil {
				continue
			}
			raw = strings.ReplaceAll(raw, "{"+name+"}", variable.Default)
		}
	}
	if raw == "" {
		return "", errors.New("base_url is required when the document has no servers entry")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", errors.New("base_url is invalid")
	}
	if !parsed.IsAbs() {
		parsed = location.ResolveReference(parsed)
	}
	if (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return "", errors.New("base_url must be a valid http(s) URL")
	}
	return strings.TrimRight(parsed.String(), "/"), nil
}

func validatePublicURL(ctx context.Context, rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Hostname() == "" {
		return errors.New("invalid URL")
	}
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, parsed.Hostname())
	if err != nil {
		return fmt.Errorf("resolve host: %w", err)
	}
	if len(addresses) == 0 {
		return errors.New("host has no addresses")
	}
	host := parsed.Hostname()
	for _, address := range addresses {
		if blockedDestination(host, address.IP) {
			return fmt.Errorf("host resolves to a blocked address %s", address.IP)
		}
	}
	return nil
}

// NewSafeHTTPClient returns an HTTP client that rejects loopback, link-local,
// and reserved destinations. RFC1918 and CGNAT addresses are allowed when the
// URL host is a DNS name (cluster-internal FQDNs) and blocked when it is a
// literal IP.
func NewSafeHTTPClient(timeout time.Duration) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		for _, resolved := range ips {
			if blockedDestination(host, resolved.IP) {
				continue
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(resolved.IP.String(), port))
		}
		return nil, fmt.Errorf("host %q resolves only to blocked addresses", host)
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("too many redirects")
			}
			if len(via) > 0 && !strings.EqualFold(req.URL.Hostname(), via[0].URL.Hostname()) {
				return errors.New("cross-host redirects are not allowed")
			}
			return nil
		},
	}
}

func blockedDestination(host string, ip net.IP) bool {
	if ipAlwaysBlocked(ip) {
		return true
	}
	if net.ParseIP(host) == nil {
		return false
	}
	return ip.IsPrivate() || cgnatIP(ip)
}

func ipAlwaysBlocked(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	address, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	address = address.Unmap()
	for _, prefix := range blockedNetworkPrefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func cgnatIP(ip net.IP) bool {
	address, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	return cgnatPrefix.Contains(address.Unmap())
}

func compileError(stage appopenapi.Stage, err error) error {
	return &appopenapi.CompileError{Stage: stage, Err: err}
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func stringSlice(value any) []string {
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		if value, ok := item.(string); ok {
			out = append(out, value)
		}
	}
	return out
}

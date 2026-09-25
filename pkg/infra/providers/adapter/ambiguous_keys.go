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

package adapter

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
)

// maxKeyDepth is the nesting encoding/json refuses to decode past, so no
// body a decoder accepts nests deeper and the scan never holds more frames.
const maxKeyDepth = 10000

var utf8BOM = []byte("\xef\xbb\xbf")

// HasAmbiguousKeys reports a request body in format f that the decoders may
// read otherwise than the upstream: a body encoding/json refuses, which a
// more lenient upstream parser may still accept, one that starts with a
// byte order mark, which Python parsers skip and encoding/json refuses, an
// object that repeats a key, where the decoder keeps the last copy and
// another parser may keep the first, or an object decoded into a struct
// with two keys the decoder matches to one field, ignoring case (and, for
// Gemini, the snake_case spelling the API also accepts).
//
// Keys that only differ in case count only where the adapter of f decodes
// the object into a struct with a field of that name. The objects a format
// leaves to the client, such as JSON schemas, tool arguments, metadata,
// documents and vendor extensions, may hold keys such as "Name" and "name":
// the decoder keeps both there, as the upstream does.
func HasAmbiguousKeys(f Format, b []byte) bool {
	return !decodableBody(b) || ambiguousKeys(b, keyShapeFor(f, b))
}

func decodableBody(b []byte) bool {
	return !bytes.HasPrefix(b, utf8BOM) && json.Valid(b)
}

func adapterFormat(ad RequestAdapter) Format {
	switch ad.(type) {
	case *OpenAIAdapter, *MistralAdapter, *OpenRouterAdapter:
		return FormatOpenAI
	case *OpenAIResponsesAdapter:
		return FormatOpenAIResponses
	case *AnthropicAdapter:
		return FormatAnthropic
	case *GeminiAdapter:
		return FormatGemini
	case *BedrockAdapter:
		return FormatBedrock
	case *CohereAdapter:
		return FormatCohere
	}
	return ""
}

// keyShapeFor returns the shape of the body the adapter of f decodes. The
// Chat adapters decode a body with input and no messages as a Responses
// request. A format without a shape has every object checked as a struct.
func keyShapeFor(f Format, b []byte) *keyShape {
	switch normalizeFormat(f) {
	case FormatOpenAI, FormatMistral:
		if isResponsesAPIRequest(b) {
			return responsesShape
		}
		return chatShape
	case FormatOpenAIResponses:
		return responsesShape
	case FormatAnthropic:
		return anthropicShape
	case FormatGemini:
		return geminiShape
	case FormatBedrock:
		return bedrockShape
	case FormatCohere:
		return cohereShape
	}
	return strictShape
}

// keyShape is an object an adapter decodes into a struct. fields maps the
// normalized name of each field to the shape of its value: an object, or an
// array whose items, at any depth, take that shape. A nil shape is a value
// the adapter keeps as a map or raw JSON, whose keys belong to the client.
type keyShape struct {
	norm   func(string) string
	fields map[string]*keyShape
	every  bool
}

// strictShape checks every key of every object as a struct field.
var strictShape = &keyShape{norm: foldKey, every: true}

// lookup returns the key under which key counts as a repeat and the shape
// of its value: the normalized field name for a field of the struct, the
// key itself for any other key, which the decoder ignores.
func (s *keyShape) lookup(key string) (string, *keyShape) {
	switch {
	case s == nil:
		return key, nil
	case s.every:
		return s.norm(key), s
	}
	norm := s.norm(key)
	child, ok := s.fields[norm]
	if !ok {
		return key, nil
	}
	return norm, child
}

func newShape(norm func(string) string, types ...any) *keyShape {
	s := &keyShape{norm: norm, fields: map[string]*keyShape{}}
	for _, v := range types {
		s.addFields(reflect.TypeOf(v))
	}
	return s
}

func (s *keyShape) addFields(t reflect.Type) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	for i := range t.NumField() {
		f := t.Field(i)
		tag, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		switch {
		case tag == "-":
		case f.Anonymous && tag == "":
			s.addFields(f.Type)
		case tag != "":
			s.key(tag)
		default:
			s.key(f.Name)
		}
	}
}

func (s *keyShape) key(names ...string) *keyShape {
	for _, n := range names {
		if _, ok := s.fields[s.norm(n)]; !ok {
			s.fields[s.norm(n)] = nil
		}
	}
	return s
}

// with sets the shape of the value of key, a field whose value the adapter
// decodes into another struct.
func (s *keyShape) with(key string, child *keyShape) *keyShape {
	s.fields[s.norm(key)] = child
	return s
}

// geminiKey folds a Gemini key as the adapter reads it: the API takes the
// lowerCamelCase and the snake_case spelling of each field.
func geminiKey(s string) string {
	return foldKey(strings.ReplaceAll(s, "_", ""))
}

func shapeOf(types ...any) *keyShape { return newShape(foldKey, types...) }

var chatShape = func() *keyShape {
	cache := shapeOf(anthropicCacheControl{})
	part := shapeOf(openaiContentPart{}).
		with("cache_control", cache).
		with("prompt_cache_breakpoint", shapeOf(openaiPromptCacheBreakpoint{}))
	call := shapeOf(openaiToolCall{}).
		with("function", shapeOf(openaiCallFunc{})).
		with("custom", shapeOf(openaiCustomCall{}))
	legacyCall := shapeOf().key("name", "arguments")
	message := shapeOf(openaiMessage{}).key("name").
		with("content", part).
		with("tool_calls", call).
		with("function_call", legacyCall)
	tool := shapeOf(openaiTool{}).
		with("function", shapeOf(openaiFunction{})).
		with("custom", shapeOf(openaiCustomTool{})).
		with("cache_control", cache)
	named := shapeOf().key("name")
	choice := shapeOf().key("type", "name").
		with("function", named).
		with("custom", named).
		with("tools", shapeOf().key("type", "name").with("function", named).with("custom", named))
	return shapeOf(openaiRequestIn{}).
		with("messages", message).
		with("tools", tool).
		with("functions", shapeOf().key("name", "description", "parameters")).
		with("function_call", named).
		with("tool_choice", choice).
		with("response_format", shapeOf(openaiChatRespFormat{}).with("json_schema", shapeOf(openaiJSONSchema{}))).
		with("prompt_cache_options", shapeOf().key("mode")).
		with("cache_control", cache)
}()

var responsesShape = func() *keyShape {
	breakpoint := shapeOf(openaiPromptCacheBreakpoint{})
	part := shapeOf(openaiContentPart{}).
		with("cache_control", shapeOf(anthropicCacheControl{})).
		with("prompt_cache_breakpoint", breakpoint)
	item := shapeOf(openaiResponsesInputItem{}).
		with("content", part).
		with("output", part).
		with("prompt_cache_breakpoint", breakpoint)
	return shapeOf(openaiResponsesRequest{}).
		with("input", item).
		with("tools", shapeOf(openaiResponsesTool{})).
		with("tool_choice", shapeOf().key("type", "name").with("tools", shapeOf().key("type", "name"))).
		with("text", shapeOf(openaiTextFormat{}).with("format", shapeOf(openaiRespFormat{}))).
		with("prompt_cache_options", shapeOf().key("mode"))
}()

var anthropicShape = func() *keyShape {
	cache := shapeOf(anthropicCacheControl{})
	block := shapeOf(anthropicContentBlock{}).
		with("cache_control", cache).
		with("source", shapeOf(anthropicImageSource{}))
	block.with("content", block)
	return shapeOf(anthropicRequest{}).
		with("system", block).
		with("messages", shapeOf(anthropicMessage{}).with("content", block)).
		with("tools", shapeOf(anthropicTool{}).key("mcp_server_name").
			with("custom", shapeOf(anthropicToolCustom{})).
			with("cache_control", cache)).
		with("tool_choice", shapeOf(anthropicToolChoice{})).
		with("mcp_servers", shapeOf().key("type", "name", "url")).
		with("cache_control", cache)
}()

var geminiShape = func() *keyShape {
	gemini := func(types ...any) *keyShape { return newShape(geminiKey, types...) }
	part := gemini(geminiPart{}).
		with("functionCall", gemini(geminiFunctionCall{})).
		with("functionResponse", gemini(geminiFuncResponse{})).
		with("inlineData", gemini().key("mimeType", "data")).
		with("fileData", gemini().key("mimeType", "fileUri"))
	content := gemini(geminiContent{}).with("parts", part)
	return gemini(geminiRequest{}).
		with("contents", content).
		with("systemInstruction", content).
		with("generationConfig", gemini(geminiGenConfig{})).
		with("tools", gemini(geminiToolGroup{}).with("functionDeclarations", gemini(geminiFuncDecl{}))).
		with("toolConfig", gemini().
			with("functionCallingConfig", gemini().key("mode", "allowedFunctionNames")))
}()

var bedrockShape = func() *keyShape {
	cachePoint := shapeOf(ConverseCachePoint{})
	image := shapeOf(ConverseImageBlock{}).with("source", shapeOf(ConverseImageSource{}))
	guard := shapeOf(ConverseGuardContent{}).
		with("text", shapeOf(ConverseGuardText{})).
		with("image", image)
	block := shapeOf(ConverseContentBlock{}).
		with("image", image).
		with("toolUse", shapeOf(ConverseToolUse{})).
		with("toolResult", shapeOf(ConverseToolResult{}).with("content", shapeOf(ConverseToolResultContent{}))).
		with("reasoningContent", shapeOf(ConverseReasoningContent{}).with("reasoningText", shapeOf(ConverseReasoningText{}))).
		with("cachePoint", cachePoint)
	named := shapeOf(ConverseSpecificTool{})
	return shapeOf(ConverseRequest{}).
		with("messages", shapeOf(ConverseMessage{}).with("content", block)).
		with("system", shapeOf(ConverseSystemBlock{}).with("guardContent", guard).with("cachePoint", cachePoint)).
		with("inferenceConfig", shapeOf(ConverseInferenceConfig{})).
		with("toolConfig", shapeOf(ConverseToolConfig{}).
			with("tools", shapeOf(ConverseTool{}).
				with("toolSpec", shapeOf(ConverseToolSpec{}).with("inputSchema", shapeOf(ConverseToolInputSchema{}))).
				with("cachePoint", cachePoint)).
			with("toolChoice", shapeOf(ConverseToolChoice{}).
				with("auto", shapeOf()).
				with("any", shapeOf()).
				with("tool", named)))
}()

var cohereShape = func() *keyShape {
	return shapeOf(cohereRequest{}).
		with("messages", shapeOf(cohereMessage{}).
			with("content", shapeOf(cohereContentBlock{})).
			with("tool_calls", shapeOf(cohereToolCall{}).with("function", shapeOf(cohereToolCallFunction{})))).
		with("tools", shapeOf(cohereTool{}).with("function", shapeOf(cohereToolFunction{}))).
		with("tool_choice", shapeOf(cohereToolChoice{}))
}()

// ambiguousKeys scans the valid JSON body b once with the shape of its root.
// It holds one frame per open container, which the depth cap bounds, and a
// frame keeps no keys until its object has some.
func ambiguousKeys(b []byte, root *keyShape) bool {
	var stack []keyFrame
	for i := 0; i < len(b); i++ {
		switch b[i] {
		case '{', '[':
			if len(stack) >= maxKeyDepth {
				return true
			}
			shape := root
			if n := len(stack); n > 0 {
				shape = stack[n-1].valueShape()
			}
			object := b[i] == '{'
			stack = append(stack, keyFrame{shape: shape, object: object, atKey: object})
		case '}', ']':
			if len(stack) == 0 {
				return true
			}
			stack = stack[:len(stack)-1]
		case ',':
			if n := len(stack); n > 0 && stack[n-1].object {
				stack[n-1].atKey = true
			}
		case '"':
			end, err := rawStringEnd(b, i)
			if err != nil {
				return true
			}
			if n := len(stack); n > 0 && stack[n-1].atKey {
				key, ok := rawString(b, rawSpan{i, end})
				if !ok || stack[n-1].repeats(key) {
					return true
				}
			}
			i = end - 1
		}
	}
	return len(stack) != 0
}

// keyFrame is one open object or array. shape is the struct the object is
// decoded into, or the one the items of the array are, nil for a value the
// client owns. next is the shape of the value of the key read last.
type keyFrame struct {
	shape, next   *keyShape
	object, atKey bool
	keys          []string
	seen          map[string]struct{}
}

func (f *keyFrame) valueShape() *keyShape {
	if f.object {
		return f.next
	}
	return f.shape
}

// keyFrameLinearKeys is how many keys an object is scanned linearly for
// repeats before it switches to a set.
const keyFrameLinearKeys = 8

func (f *keyFrame) repeats(key string) bool {
	k, next := f.shape.lookup(key)
	f.next, f.atKey = next, false
	if f.seen == nil {
		for _, seen := range f.keys {
			if seen == k {
				return true
			}
		}
		if f.keys = append(f.keys, k); len(f.keys) <= keyFrameLinearKeys {
			return false
		}
		f.seen = make(map[string]struct{}, 2*keyFrameLinearKeys)
		for _, seen := range f.keys {
			f.seen[seen] = struct{}{}
		}
		f.keys = nil
		return false
	}
	if _, dup := f.seen[k]; dup {
		return true
	}
	f.seen[k] = struct{}{}
	return false
}

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
	"bytes"
	"errors"
	"io"
	"slices"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/html"
)

const maxAppsHTMLAttributes, maxAppsHTMLDepth, maxAppsHTMLNodes, maxAppsHTMLTokens = 64, 128, 2048, 4096

var errAppsHTML, appsHTMLBOM, appsHTMLVoidTags = errors.New("invalid HTML"), []byte{0xEF, 0xBB, 0xBF}, map[string]bool{
	"area": true, "base": true, "br": true, "col": true, "embed": true, "hr": true, "img": true, "input": true, "link": true, "meta": true, "param": true,
	"source": true, "track": true, "wbr": true,
}

type appsHTMLStackEntry struct {
	name, namespace string
	htmlChildren    bool
}
type appsHTMLSignature struct {
	kind            byte
	name, namespace string
	depth           int
}
type appsHTMLState struct {
	doctype, rootClosed bool
	head, body          uint8
	stack               []appsHTMLStackEntry
	signature           []appsHTMLSignature
}

func validateAppsHTML(body []byte) error {
	if !utf8.Valid(body) {
		return errAppsHTML
	}
	body = bytes.TrimPrefix(body, appsHTMLBOM)
	if bytes.Contains(body, appsHTMLBOM) {
		return errAppsHTML
	}
	for _, value := range body {
		if value == 0 || value < 0x20 && value != '\t' && value != '\n' && value != '\r' {
			return errAppsHTML
		}
	}
	strict, err := strictAppsHTMLSignature(body)
	if err != nil {
		return err
	}
	parsed, err := parsedAppsHTMLSignature(body)
	if err != nil || !slices.Equal(strict, parsed) {
		return errAppsHTML
	}
	return nil
}
func strictAppsHTMLSignature(body []byte) ([]appsHTMLSignature, error) {
	state := appsHTMLState{stack: make([]appsHTMLStackEntry, 0, 16), signature: make([]appsHTMLSignature, 0, 32)}
	tokenizer := html.NewTokenizer(bytes.NewReader(body))
	for tokens := 0; ; tokens++ {
		tokenType := tokenizer.Next()
		if tokenType == html.ErrorToken {
			if errors.Is(tokenizer.Err(), io.EOF) {
				break
			}
			return nil, errAppsHTML
		}
		if tokens >= maxAppsHTMLTokens {
			return nil, errAppsHTML
		}
		switch tokenType {
		case html.DoctypeToken:
			if state.doctype || len(state.stack) != 0 || state.rootClosed ||
				!strings.EqualFold(string(tokenizer.Raw()), "<!doctype html>") {
				return nil, errAppsHTML
			}
			state.doctype = true
			state.signature = append(state.signature, appsHTMLSignature{kind: 'D'})
		case html.StartTagToken, html.SelfClosingTagToken:
			if err := validateAppsHTMLRawStart(tokenizer.Raw()); err != nil {
				return nil, err
			}
			if err := state.open(tokenizer.Token(), tokenType == html.SelfClosingTagToken); err != nil {
				return nil, err
			}
		case html.EndTagToken:
			if err := state.close(tokenizer.Token()); err != nil {
				return nil, err
			}
		case html.TextToken:
			text := tokenizer.Token().Data
			if strings.Trim(text, " \t\r\n") != "" {
				if len(state.stack) == 0 || len(state.stack) == 1 && state.stack[0].name == "html" {
					return nil, errAppsHTML
				}
				state.signature = append(state.signature, appsHTMLSignature{kind: 'T', depth: len(state.stack)})
			}
		case html.CommentToken:
			raw := tokenizer.Raw()
			if !state.doctype || len(raw) < len("<!---->") || !bytes.HasPrefix(raw, []byte("<!--")) || !bytes.HasSuffix(raw, []byte("-->")) {
				return nil, errAppsHTML
			}
		default:
			return nil, errAppsHTML
		}
	}
	if !state.doctype || !state.rootClosed || state.head != 2 || state.body != 2 || len(state.stack) != 0 {
		return nil, errAppsHTML
	}
	return state.signature, nil
}
func (s *appsHTMLState) open(token html.Token, selfClosing bool) error {
	name := strings.ToLower(token.Data)
	if !s.doctype || s.rootClosed || len(token.Attr) > maxAppsHTMLAttributes {
		return errAppsHTML
	}
	namespace := appsHTMLChildNamespace(s.stack, name)
	if len(s.stack) == 0 {
		if name != "html" || namespace != "" || selfClosing {
			return errAppsHTML
		}
	} else {
		parent := s.stack[len(s.stack)-1]
		if parent.namespace == "" && parent.name == "html" {
			switch {
			case s.head == 0 && name == "head":
				s.head = 1
			case s.head == 2 && s.body == 0 && name == "body":
				s.body = 1
			default:
				return errAppsHTML
			}
		} else if namespace == "" && (name == "html" || name == "head" || name == "body") {
			return errAppsHTML
		}
	}
	depth := len(s.stack)
	s.signature = append(s.signature, appsHTMLSignature{kind: '+', name: name, namespace: namespace, depth: depth})
	if namespace == "" && appsHTMLVoidTags[name] || selfClosing {
		if namespace == "" && !appsHTMLVoidTags[name] {
			return errAppsHTML
		}
		s.signature = append(s.signature, appsHTMLSignature{kind: '-', name: name, namespace: namespace, depth: depth})
		return nil
	}
	if len(s.stack) >= maxAppsHTMLDepth {
		return errAppsHTML
	}
	s.stack = append(s.stack, appsHTMLStackEntry{
		name:         name,
		namespace:    namespace,
		htmlChildren: appsHTMLIntegrationPoint(namespace, name, token.Attr),
	})
	return nil
}
func (s *appsHTMLState) close(token html.Token) error {
	if len(s.stack) == 0 {
		return errAppsHTML
	}
	name := strings.ToLower(token.Data)
	top := s.stack[len(s.stack)-1]
	if name != top.name {
		return errAppsHTML
	}
	switch {
	case top.namespace == "" && name == "head":
		s.head = 2
	case top.namespace == "" && name == "body":
		s.body = 2
	case top.namespace == "" && name == "html":
		if s.head != 2 || s.body != 2 {
			return errAppsHTML
		}
		s.rootClosed = true
	}
	depth := len(s.stack) - 1
	s.signature = append(s.signature, appsHTMLSignature{kind: '-', name: name, namespace: top.namespace, depth: depth})
	s.stack = s.stack[:depth]
	return nil
}
func appsHTMLChildNamespace(stack []appsHTMLStackEntry, name string) string {
	if len(stack) == 0 {
		return ""
	}
	parent := stack[len(stack)-1]
	if parent.htmlChildren {
		if parent.namespace == "math" && (name == "mglyph" || name == "malignmark") {
			return "math"
		}
		if name == "svg" {
			return "svg"
		}
		if name == "math" {
			return "math"
		}
		return ""
	}
	return parent.namespace
}
func validateAppsHTMLRawStart(raw []byte) error {
	index := appsHTMLScan(raw, 1, " \t\r\n/>")
	var attributes [maxAppsHTMLAttributes][2]int
	count := 0
	for {
		before := index
		index += len(raw[index:]) - len(bytes.TrimLeft(raw[index:], " \t\r\n"))
		if index >= len(raw) || raw[index] == '>' || raw[index] == '/' && index+1 < len(raw) && raw[index+1] == '>' {
			return nil
		}
		start := index
		index = appsHTMLScan(raw, index, " \t\r\n=/>\"'<")
		if before == start || start == index {
			return errAppsHTML
		}
		if count >= maxAppsHTMLAttributes {
			return errAppsHTML
		}
		for _, attribute := range attributes[:count] {
			if bytes.EqualFold(raw[start:index], raw[attribute[0]:attribute[1]]) {
				return errAppsHTML
			}
		}
		attributes[count], count = [2]int{start, index}, count+1
		index += len(raw[index:]) - len(bytes.TrimLeft(raw[index:], " \t\r\n"))
		if index >= len(raw) || raw[index] != '=' {
			continue
		}
		index++
		index += len(raw[index:]) - len(bytes.TrimLeft(raw[index:], " \t\r\n"))
		if index >= len(raw) {
			return errAppsHTML
		}
		if raw[index] == '"' || raw[index] == '\'' {
			quote := raw[index]
			index++
			end := bytes.IndexByte(raw[index:], quote)
			if end < 0 {
				return errAppsHTML
			}
			index += end + 1
			continue
		}
		start = index
		index = appsHTMLScan(raw, index, " \t\r\n>")
		if start == index || bytes.ContainsAny(raw[start:index], "\"'<=") {
			return errAppsHTML
		}
	}
}
func appsHTMLScan(raw []byte, index int, stop string) int {
	for index < len(raw) && strings.IndexByte(stop, raw[index]) < 0 {
		index++
	}
	return index
}
func appsHTMLIntegrationPoint(namespace, name string, attributes []html.Attribute) bool {
	if namespace == "svg" {
		return name == "foreignobject"
	}
	if namespace != "math" {
		return namespace == ""
	}
	if name == "mi" || name == "mo" || name == "mn" || name == "ms" || name == "mtext" {
		return true
	}
	if name != "annotation-xml" {
		return false
	}
	for _, attribute := range attributes {
		if strings.EqualFold(attribute.Key, "encoding") &&
			(strings.EqualFold(attribute.Val, "text/html") || strings.EqualFold(attribute.Val, "application/xhtml+xml")) {
			return true
		}
	}
	return false
}
func parsedAppsHTMLSignature(body []byte) ([]appsHTMLSignature, error) {
	document, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return nil, errAppsHTML
	}
	signature := make([]appsHTMLSignature, 0, 32)
	nodes := 0
	var visit func(*html.Node, int) error
	visit = func(node *html.Node, depth int) error {
		nodes++
		if nodes > maxAppsHTMLNodes {
			return errAppsHTML
		}
		switch node.Type {
		case html.DoctypeNode:
			signature = append(signature, appsHTMLSignature{kind: 'D'})
		case html.ElementNode:
			name, namespace := strings.ToLower(node.Data), strings.ToLower(node.Namespace)
			signature = append(signature, appsHTMLSignature{kind: '+', name: name, namespace: namespace, depth: depth})
			for child := node.FirstChild; child != nil; child = child.NextSibling {
				if err := visit(child, depth+1); err != nil {
					return err
				}
			}
			signature = append(signature, appsHTMLSignature{kind: '-', name: name, namespace: namespace, depth: depth})
			return nil
		case html.TextNode:
			if strings.Trim(node.Data, " \t\r\n") != "" {
				signature = append(signature, appsHTMLSignature{kind: 'T', depth: depth})
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			if err := visit(child, depth); err != nil {
				return err
			}
		}
		return nil
	}
	if err := visit(document, 0); err != nil {
		return nil, err
	}
	return signature, nil
}

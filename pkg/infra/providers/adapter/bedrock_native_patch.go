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
	"errors"
	"sort"
	"strconv"
	"strings"
)

var errSignedBlock = errors.New("a substitution would change a signed block")

// jnode is a JSON value with the byte span it occupies in the body. kind is 'o'
// for an object, 'a' for an array, 's' for a string and 'x' for a number, boolean
// or null. vals holds the value of keys[i] for an object and the items of an array;
// str is the decoded value of a string and raw the literal text of a scalar.
type jnode struct {
	kind       byte
	start, end int
	keys       []string
	vals       []*jnode
	str        string
	raw        string
}

func (n *jnode) member(key string) *jnode {
	for i, k := range n.keys {
		if k == key {
			return n.vals[i]
		}
	}
	return nil
}

func (n *jnode) strMember(key string) string {
	if m := n.member(key); m != nil && m.kind == 's' {
		return m.str
	}
	return ""
}

func parseJSON(body []byte) (*jnode, bool) {
	if !json.Valid(body) {
		return nil, false
	}
	p := &jparser{b: body}
	p.skip()
	n := p.value()
	return n, n != nil
}

type jparser struct {
	b []byte
	i int
}

func (p *jparser) skip() {
	for p.i < len(p.b) {
		switch p.b[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		default:
			return
		}
	}
}

func (p *jparser) value() *jnode {
	switch p.b[p.i] {
	case '{':
		n := &jnode{kind: 'o', start: p.i}
		p.i++
		for {
			p.skip()
			if p.b[p.i] == '}' {
				p.i++
				break
			}
			if p.b[p.i] == ',' {
				p.i++
				continue
			}
			key := p.str()
			p.skip()
			p.i++
			p.skip()
			n.keys = append(n.keys, key.str)
			n.vals = append(n.vals, p.value())
		}
		n.end = p.i
		return n
	case '[':
		n := &jnode{kind: 'a', start: p.i}
		p.i++
		for {
			p.skip()
			if p.b[p.i] == ']' {
				p.i++
				break
			}
			if p.b[p.i] == ',' {
				p.i++
				continue
			}
			n.vals = append(n.vals, p.value())
		}
		n.end = p.i
		return n
	case '"':
		return p.str()
	default:
		n := &jnode{kind: 'x', start: p.i}
		for p.i < len(p.b) && !strings.ContainsRune(",]} \t\n\r", rune(p.b[p.i])) {
			p.i++
		}
		n.end = p.i
		n.raw = string(p.b[n.start:n.end])
		return n
	}
}

func (p *jparser) str() *jnode {
	n := &jnode{kind: 's', start: p.i}
	p.i++
	for p.b[p.i] != '"' {
		if p.b[p.i] == '\\' {
			p.i++
		}
		p.i++
	}
	p.i++
	n.end = p.i
	// The body was validated by json.Valid before it was parsed into spans, so the
	// literal is a well-formed string: the unmarshal cannot fail here. If it ever
	// did, n.str stays empty and nothing is patched at the string.
	if err := json.Unmarshal(p.b[n.start:n.end], &n.str); err != nil {
		n.str = ""
	}
	p.skip()
	return n
}

// targetKind is what a patch target holds: a string the view reads, or the base64
// of a text document the view reads.
type targetKind int

const (
	targetText targetKind = iota
	targetBase64
)

type patchTarget struct {
	node *jnode
	kind targetKind
	// signed marks a string inside an object that carries a signature.
	signed bool
}

func targets(root *jnode) []patchTarget {
	var out []patchTarget
	var walk func(n *jnode, inTool, signed bool)
	walk = func(n *jnode, inTool, signed bool) {
		switch n.kind {
		case 's':
			if !isBinaryBlob(n.str) {
				out = append(out, patchTarget{node: n, kind: targetText, signed: signed})
			}
		case 'a':
			for _, item := range n.vals {
				walk(item, inTool, signed)
			}
		case 'o':
			signed = signed || n.member("signature") != nil
			if doc := documentTarget(n); doc != nil {
				doc.signed = signed
				out = append(out, *doc)
			}
			inTool = inTool || n.strMember("type") == "tool_use"
			for i, k := range n.keys {
				lk := strings.ToLower(k)
				switch {
				case lk == "name" && inTool:
					continue
				case lk == "data" && n.strMember("type") == "base64":
					continue
				case lk == "properties":
					// The keys of a schema are read too, but a key cannot be masked.
				case isNonTextKey(k):
					continue
				}
				_, tool := toolKeys[lk]
				walk(n.vals[i], inTool || tool, signed)
			}
		}
	}
	walk(root, false, false)
	return out
}

// documentSourceString is the string holding the bytes of a text document, the
// one the view reads when it decodes: a Converse document of a text format, or an
// Anthropic base64 source whose media type is text. It does not say the string
// decodes.
func documentSourceString(n *jnode) *jnode {
	src := n.member("source")
	if src == nil || src.kind != 'o' {
		return nil
	}
	if _, text := textDocumentFormats[strings.ToLower(n.strMember("format"))]; text {
		if b := src.member("bytes"); b != nil && b.kind == 's' {
			return b
		}
	}
	if src.strMember("type") == "base64" && strings.HasPrefix(strings.ToLower(src.strMember("media_type")), "text/") {
		if d := src.member("data"); d != nil && d.kind == 's' {
			return d
		}
	}
	return nil
}

func documentTarget(n *jnode) *patchTarget {
	if s := documentSourceString(n); s != nil && decodedText(s.str) != "" {
		return &patchTarget{node: s, kind: targetBase64}
	}
	return nil
}

func (t patchTarget) text() string {
	if t.kind == targetBase64 {
		return decodedText(t.node.str)
	}
	return t.node.str
}

func sortedTargets(root *jnode) []patchTarget {
	ts := targets(root)
	sort.SliceStable(ts, func(i, j int) bool { return ts[i].node.start < ts[j].node.start })
	return ts
}

type placedEdit struct {
	off      int
	from, to string
}

// maskString applies the long substitutions to every part of s and the placed
// edits at their offsets only. An edit that does not find its text where it was
// said to be is an error: the offsets and the text no longer agree, and nothing
// is sent.
func maskString(s string, subs []Substitution, placed []placedEdit) (string, error) {
	if len(placed) == 0 {
		return substituteString(s, subs), nil
	}
	sort.Slice(placed, func(i, j int) bool { return placed[i].off < placed[j].off })
	var sb strings.Builder
	cur := 0
	for _, e := range placed {
		end := e.off + len(e.from)
		if e.off < cur || end > len(s) || s[e.off:end] != e.from {
			return "", errors.New("a placed substitution does not match the text it was found in")
		}
		sb.WriteString(substituteString(s[cur:e.off], subs))
		sb.WriteString(e.to)
		cur = end
	}
	sb.WriteString(substituteString(s[cur:], subs))
	return sb.String(), nil
}

// patchInPlace writes the substitutions into the bytes the client sent. The body is
// parsed into spans, the strings the view reads are found with the same rules the
// view uses to read them, and only those strings are rewritten; every other byte,
// whitespace, key order, number literal, escape and identifier included, is copied
// as it was.
func patchInPlace(body []byte, subs []Substitution) ([]byte, error) {
	root, ok := parseJSON(body)
	if !ok {
		return nil, errors.New("the body is not JSON")
	}
	applied := orderedForPatch(subs)
	placed := map[int][]placedEdit{}
	for _, s := range subs {
		if !s.short() {
			continue
		}
		for _, p := range s.Places {
			placed[p.Target] = append(placed[p.Target], placedEdit{off: p.Off, from: s.From, to: s.To})
		}
	}
	var out bytes.Buffer
	cur := 0
	edits := sortedTargets(root)
	for i, t := range edits {
		old := t.text()
		masked, err := maskString(old, applied, placed[i])
		if err != nil {
			return nil, err
		}
		if masked == old {
			continue
		}
		if t.signed {
			return nil, errSignedBlock
		}
		literal := masked
		if t.kind == targetBase64 {
			_, raw, _ := decodeDocument(t.node.str)
			literal = encodeDocument(masked, raw)
		}
		quoted, err := marshalNoEscape(literal)
		if err != nil {
			return nil, err
		}
		out.Write(body[cur:t.node.start])
		out.Write(quoted)
		cur = t.node.end
	}
	out.Write(body[cur:])
	return out.Bytes(), nil
}

func skeleton(body []byte) ([]byte, bool) {
	root, ok := parseJSON(body)
	if !ok {
		return nil, false
	}
	var cuts []patchTarget
	for _, t := range targets(root) {
		if !t.signed {
			cuts = append(cuts, t)
		}
	}
	sort.SliceStable(cuts, func(i, j int) bool { return cuts[i].node.start < cuts[j].node.start })
	var out bytes.Buffer
	cur := 0
	for _, t := range cuts {
		out.Write(body[cur:t.node.start])
		cur = t.node.end
	}
	out.Write(body[cur:])
	return out.Bytes(), true
}

func onlyReadStringsChanged(original, masked []byte) bool {
	a, ok := skeleton(original)
	if !ok {
		return false
	}
	b, ok := skeleton(masked)
	return ok && bytes.Equal(a, b)
}

// treeLeaks is the leak check that does not depend on the view's text: it looks
// at every object key, every number, and every string the view reads, including
// the decoded text of base64 documents and signed blocks, for removed text.
func treeLeaks(body []byte, subs []Substitution) bool {
	root, ok := parseJSON(body)
	if !ok {
		return true
	}
	has := func(s string) bool {
		for _, sub := range subs {
			if !sub.short() && strings.TrimSpace(sub.From) != "" && strings.Contains(s, sub.From) {
				return true
			}
		}
		return false
	}
	for _, t := range targets(root) {
		if has(t.text()) {
			return true
		}
	}
	var walk func(n *jnode) bool
	walk = func(n *jnode) bool {
		switch n.kind {
		case 'x':
			return has(n.raw)
		case 'a':
			for _, v := range n.vals {
				if walk(v) {
					return true
				}
			}
		case 'o':
			for i, k := range n.keys {
				if has(k) || walk(n.vals[i]) {
					return true
				}
			}
		}
		return false
	}
	return walk(root)
}

// The tags a string is wrapped in to see where it lands in a view. They are
// private-use code points, so a body that carries one is simply not placed.
const (
	tagOpen     = ''
	tagOpenEnd  = ''
	tagClose    = ''
	tagCloseEnd = ''
	tagRunes    = ""
)

type viewSpan struct {
	target, start, end int
}

// viewSpans maps the text a plugin saw back to the strings it was read from. It
// wraps each string the view reads in a pair of tags, reads the copy with the
// same decoders, and reads the tags back out of the resulting text: where a
// string landed is then known by construction, in whatever order or joined
// however the decoders put it. The text with the tags removed must be exactly
// the view of the real body and every wrapped string must come back unchanged;
// if a decoder did anything else with a string (trimmed it, merged it with
// another, dropped a repeat of it), the mapping cannot be trusted and ok is
// false.
func viewSpans(body []byte, view string, decode func([]byte) (string, error)) ([]viewSpan, bool) {
	if strings.ContainsAny(view, tagRunes) {
		return nil, false
	}
	root, ok := parseJSON(body)
	if !ok {
		return nil, false
	}
	ts := sortedTargets(root)
	var out bytes.Buffer
	cur := 0
	for i, t := range ts {
		wrapped := string(tagOpen) + strconv.Itoa(i) + string(tagOpenEnd) + t.text() +
			string(tagClose) + strconv.Itoa(i) + string(tagCloseEnd)
		if t.kind == targetBase64 {
			_, raw, _ := decodeDocument(t.node.str)
			wrapped = encodeDocument(wrapped, raw)
		}
		quoted, err := marshalNoEscape(wrapped)
		if err != nil {
			return nil, false
		}
		out.Write(body[cur:t.node.start])
		out.Write(quoted)
		cur = t.node.end
	}
	out.Write(body[cur:])
	tagged, err := decode(out.Bytes())
	if err != nil {
		return nil, false
	}

	var (
		plain  strings.Builder
		spans  []viewSpan
		starts = map[int]int{}
	)
	rs := []rune(tagged)
	number := func(i int, end rune) (n, next int, ok bool) {
		j := i
		for j < len(rs) && rs[j] >= '0' && rs[j] <= '9' {
			j++
		}
		if j == i || j >= len(rs) || rs[j] != end {
			return 0, 0, false
		}
		n, err := strconv.Atoi(string(rs[i:j]))
		return n, j + 1, err == nil
	}
	for i := 0; i < len(rs); {
		switch rs[i] {
		case tagOpen:
			n, next, ok := number(i+1, tagOpenEnd)
			if !ok {
				return nil, false
			}
			starts[n] = plain.Len()
			i = next
		case tagClose:
			n, next, ok := number(i+1, tagCloseEnd)
			if !ok {
				return nil, false
			}
			start, open := starts[n]
			if !open || n >= len(ts) || plain.String()[start:] != ts[n].text() {
				return nil, false
			}
			spans = append(spans, viewSpan{target: n, start: start, end: plain.Len()})
			delete(starts, n)
			i = next
		default:
			plain.WriteRune(rs[i])
			i++
		}
	}
	if len(starts) != 0 || plain.String() != view {
		return nil, false
	}
	return spans, true
}

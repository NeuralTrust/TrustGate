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

package promptcompression

// mayCompress reports whether any transform enabled in cfg could change the
// request, in one pass over the raw body and without allocating per value.
// Most requests hold nothing to compress, and for them this replaces the
// round-trip guards, the decode and the per-message transforms.
//
// It never misses a change the pipeline would make; a false positive only
// costs the full pipeline. To stay on the safe side it decodes string escapes,
// so it sees the text the transforms see, and it reads the text blocks of one
// content or system array as the decoders join them, with "\n", before
// applying MinLength to the joined text. A body it cannot follow (malformed
// JSON, deep nesting) takes the full pipeline, which fails open on its own.
func mayCompress(body []byte, cfg Settings) bool {
	s := bodyScan{body: body, cfg: cfg, stack: make([]scanFrame, 0, 16)}
	return s.run()
}

// fencePrefix opens a Markdown block the fenced-JSON transform minifies.
const fencePrefix = "```json"

// maxScanDepth bounds the container stack; deeper bodies take the full
// pipeline.
const maxScanDepth = 256

// nonASCII stands for any character at or above U+0080 once decoded: none of
// them matter to the transforms, except that strings.TrimSpace treats a few
// as space, so the JSON check counts them as whitespace.
const nonASCII = 0x80

// plainByte marks the bytes the scan can skip over in bulk outside a JSON
// document: they end a run of newlines, and only a space matters beyond
// that, as the last byte of a stretch or in text that is only spaces.
var plainByte = func() (t [256]bool) {
	for c := 0x20; c < 0x7f; c++ {
		t[c] = c != '"' && c != '\\' && c != '`'
	}
	return t
}()

type valueKind uint8

const (
	valueOther valueKind = iota
	// valueText strings become system or message text, on their own or
	// joined with the other text blocks of their array.
	valueText
	// valueArgs holds tool-call arguments, which the JSON transform minifies
	// whole: a JSON string (Chat Completions) or object (Anthropic input).
	valueArgs
	// valueRole names a message's role. The Chat Completions decoder merges
	// every system and developer message into one text, wherever they sit,
	// so a body with two of them takes the full pipeline.
	valueRole
)

type scanFrame struct {
	object    bool
	expectKey bool
	// key is the kind of the member whose value comes next (objects).
	key valueKind
	// inherited is the kind of the member this container is the value of;
	// array elements take it.
	inherited valueKind
}

// textGroup is one text as the decoders build it: a lone string, or the text
// blocks of one array joined with "\n".
type textGroup struct {
	open bool
	// depth is the stack depth of the array holding the blocks, 0 for a lone
	// string.
	depth int
	parts int
	// size bounds the joined text's length in bytes, joiners included.
	size int
	// pending is set once a transform would change the text, which it does
	// when size reaches MinLength.
	pending bool
	// What the previous block left for the next one.
	trailRun int  // newlines ending it
	leadRun  int  // newlines from the start of the text while it held only newlines
	allNL    bool // it held nothing but newlines
	allSpace bool // it was empty or only whitespace
	jsonDone bool // it was exactly one JSON document
}

type bodyScan struct {
	body  []byte
	cfg   Settings
	stack []scanFrame
	group textGroup
	// argsDepth is the stack depth of the open arguments object, 0 when none.
	argsDepth int
	argsStart int
	argsSpace bool
	// systemRoles counts system and developer messages.
	systemRoles int
}

func (s *bodyScan) run() bool {
	b := s.body
	for i := 0; i < len(b); i++ {
		switch c := b[i]; c {
		case ' ', '\t', '\n', '\r':
			if s.argsDepth > 0 {
				s.argsSpace = true
			}
		case '{', '[':
			if len(s.stack) >= maxScanDepth {
				return true
			}
			kind := s.valueKind()
			s.stack = append(s.stack, scanFrame{object: c == '{', expectKey: c == '{', inherited: kind})
			if kind == valueArgs && s.argsDepth == 0 {
				s.argsDepth, s.argsStart, s.argsSpace = len(s.stack), i, false
			}
		case '}', ']':
			if len(s.stack) == 0 {
				return true
			}
			if s.argsDepth == len(s.stack) {
				if s.cfg.CompressJSON && s.argsSpace && i-s.argsStart+1 >= s.cfg.MinLength {
					return true
				}
				s.argsDepth = 0
			}
			if s.group.open && s.group.depth == len(s.stack) {
				s.group = textGroup{}
			}
			s.stack = s.stack[:len(s.stack)-1]
		case ',':
			if n := len(s.stack); n > 0 && s.stack[n-1].object {
				s.stack[n-1].expectKey = true
			}
		case '"':
			end, hit := s.str(i)
			if hit || end < 0 {
				return true
			}
			i = end
		}
	}
	return false
}

// valueKind is the kind of the value that starts at the current position.
// Nothing inside an arguments object is text: the decoders keep it whole.
func (s *bodyScan) valueKind() valueKind {
	n := len(s.stack)
	if n == 0 || s.argsDepth > 0 {
		return valueOther
	}
	if top := s.stack[n-1]; top.object {
		return top.key
	}
	return s.stack[n-1].inherited
}

// str scans the string opening at b[i] and returns the index of its closing
// quote, or -1 when the string is malformed. hit reports a possible change.
func (s *bodyScan) str(i int) (end int, hit bool) {
	if n := len(s.stack); n > 0 && s.stack[n-1].object && s.stack[n-1].expectKey {
		// Member names match case-insensitively, as encoding/json does.
		end, name := shortString(s.body, i, true)
		s.stack[n-1].key, s.stack[n-1].expectKey = classifyKey(name), false
		return end, false
	}
	switch s.valueKind() {
	case valueText:
		return s.text(i)
	case valueArgs:
		if s.cfg.CompressJSON {
			return s.args(i)
		}
	case valueRole:
		end, role := shortString(s.body, i, false)
		if role == "system" || role == "developer" {
			s.systemRoles++
		}
		return end, s.systemRoles > 1
	}
	return skipString(s.body, i), false
}

func classifyKey(name string) valueKind {
	switch name {
	case "content", "text", "system":
		return valueText
	case "arguments", "input":
		return valueArgs
	case "role":
		return valueRole
	}
	return valueOther
}

// shortString decodes the string opening at b[i] when it is at most 12 bytes
// long, folding ASCII to lower case if asked; longer strings decode to "".
// end is -1 when the string is malformed.
func shortString(b []byte, i int, fold bool) (end int, s string) {
	var buf [12]byte
	n := 0
	for j := i + 1; j < len(b); {
		if b[j] == '"' {
			if n > len(buf) {
				return j, ""
			}
			return j, string(buf[:n])
		}
		c, width, _, ok := decodeChar(b, j)
		if !ok {
			return -1, ""
		}
		if n < len(buf) {
			if fold && 'A' <= c && c <= 'Z' {
				c += 'a' - 'A'
			}
			buf[n] = c
		}
		n++
		j += width
	}
	return -1, ""
}

// enterText returns the group the text value about to be read belongs to:
// the open array group while the scan is still inside its array, a new array
// group for a block of a text array, or a new lone group.
func (s *bodyScan) enterText() *textGroup {
	n := len(s.stack)
	if g := &s.group; g.open && g.depth > 0 && n >= g.depth {
		return g
	}
	depth := 0
	switch {
	case n > 0 && !s.stack[n-1].object && s.stack[n-1].inherited == valueText:
		depth = n
	case n > 1 && s.stack[n-1].object && !s.stack[n-2].object && s.stack[n-2].inherited == valueText:
		depth = n - 1
	}
	s.group = textGroup{open: true, depth: depth}
	return &s.group
}

// text checks a value that becomes system or message text against every
// enabled transform, with the state the previous block of its group left.
func (s *bodyScan) text(i int) (int, bool) {
	cfg, b := s.cfg, s.body
	g := s.enterText()
	maxBlank, minLen := cfg.MaxConsecutiveBlankLines, cfg.MinLength
	size, pending := g.size, g.pending
	run, lead := 0, 0
	if g.parts > 0 {
		size++
		run = g.trailRun + 1
		if g.allNL {
			lead = g.leadRun + 1
		}
		// A run carried across the joiner can be complete before this block
		// adds a character: "\n" followed by "b" opens the text with "\n\n".
		if cfg.NormalizeWhitespace && (run > maxBlank+1 || lead > maxBlank) {
			pending = true
		}
	}
	afterSpace, afterJSON := g.parts > 0 && g.allSpace, g.parts > 0 && g.jsonDone
	inLead, prevSpace := true, false
	allNL, allSpace := true, true
	var probe jsonProbe
	if !cfg.CompressJSON {
		probe.state = jsonNot
	}
	fence := 0
	for j := i + 1; j < len(b); {
		if pending && size >= minLen {
			return j, true
		}
		if fence == 0 && (probe.state == jsonNot || probe.state == jsonIn && probe.inStr && !probe.esc) {
			k := j
			for k < len(b) && plainByte[b[k]] {
				k++
			}
			if k > j {
				if allSpace {
					for _, x := range b[j:k] {
						if x != ' ' {
							allSpace = false
							break
						}
					}
				}
				size += k - j
				run, inLead, allNL = 0, false, false
				prevSpace = b[k-1] == ' '
				j = k
				continue
			}
		}
		if b[j] == '"' {
			if cfg.NormalizeWhitespace && (prevSpace || run > maxBlank) {
				pending = true
			}
			if cfg.CompressJSON && (probe.state == jsonIn || afterJSON && allSpace) {
				pending = true
			}
			if pending && size >= minLen {
				return j, true
			}
			*g = textGroup{
				open: true, depth: g.depth, parts: g.parts + 1, size: size, pending: pending,
				trailRun: run, allNL: allNL, allSpace: allSpace, jsonDone: probe.state == jsonDone,
			}
			if allNL {
				g.leadRun = lead
			}
			if g.depth == 0 {
				s.group = textGroup{}
			}
			return j, false
		}
		c, width, n, ok := decodeChar(b, j)
		if !ok {
			return -1, false
		}
		j += width
		size += n
		if cfg.StripANSI && c == 0x1b {
			pending = true
		}
		if cfg.NormalizeWhitespace {
			if c == '\n' {
				run++
				if inLead {
					lead++
				}
				if prevSpace || run > maxBlank+1 || inLead && lead > maxBlank {
					pending = true
				}
			} else {
				run, inLead = 0, false
			}
			prevSpace = c == ' ' || c == '\t'
		}
		allNL = allNL && c == '\n'
		allSpace = allSpace && isSpace(c)
		if cfg.CompressJSON {
			if probe.feed(c) || afterSpace && probe.opened {
				pending = true
			}
			probe.opened = false
			if fence = matchFence(fence, c); fence == len(fencePrefix) {
				pending, fence = true, 0
			}
		}
	}
	return -1, false
}

// args checks a tool-call arguments string: the JSON transform minifies it
// whole when it is at least MinLength bytes. Unlike message text, arguments
// are minified whatever JSON value they hold, so space around a number or a
// literal counts too.
func (s *bodyScan) args(i int) (int, bool) {
	b := s.body
	var probe jsonProbe
	change, last := false, byte(0)
	size := 0
	for j := i + 1; j < len(b); {
		if change && size >= s.cfg.MinLength {
			return j, true
		}
		if probe.state == jsonNot || probe.state == jsonIn && probe.inStr && !probe.esc {
			k := j
			for k < len(b) && plainByte[b[k]] {
				k++
			}
			if k > j {
				size += k - j
				last = b[k-1]
				j = k
				continue
			}
		}
		if b[j] == '"' {
			return j, (change || isSpace(last)) && size >= s.cfg.MinLength
		}
		c, width, n, ok := decodeChar(b, j)
		if !ok {
			return -1, false
		}
		j += width
		size += n
		change = change || probe.feed(c) || size == n && isSpace(c)
		last = c
	}
	return -1, false
}

const (
	jsonLead uint8 = iota
	jsonIn
	jsonDone
	jsonNot
)

// jsonProbe follows text the way compactJSON reads it: optional whitespace,
// then a document opening with { or [. feed reports whitespace compactJSON
// would remove: before the document, between its tokens, or after it.
type jsonProbe struct {
	state uint8
	depth int
	lead  bool
	inStr bool
	esc   bool
	first bool
	space bool
	// opened is set by the character that opened the document.
	opened bool
}

func (p *jsonProbe) feed(c byte) bool {
	switch p.state {
	case jsonLead:
		switch {
		case isSpace(c):
			p.lead = true
		case c == '{' || c == '[':
			p.state, p.depth, p.first, p.opened = jsonIn, 1, true, true
			return p.lead
		default:
			p.state = jsonNot
		}
	case jsonIn:
		if p.inStr {
			switch {
			case p.esc:
				p.esc = false
			case c == '\\':
				p.esc = true
			case c == '"':
				p.inStr = false
			}
			return false
		}
		if isSpace(c) {
			if p.first {
				p.space = true
				return false
			}
			return true
		}
		if p.first {
			// Text such as "[INFO] ..." or "{name}" opens like JSON but is
			// not; only a token JSON allows here keeps the probe going.
			p.first = false
			if !startsJSONValue(c) && c != '}' {
				p.state = jsonNot
				return false
			}
			if p.space {
				return true
			}
		}
		switch c {
		case '"':
			p.inStr = true
		case '{', '[':
			p.depth++
			p.first = true
			p.space = false
		case '}', ']':
			p.depth--
			if p.depth == 0 {
				p.state = jsonDone
			}
		}
	case jsonDone:
		if isSpace(c) {
			return true
		}
		p.state = jsonNot
	}
	return false
}

func startsJSONValue(c byte) bool {
	switch c {
	case '"', '{', '[', ']', '-', 't', 'f', 'n':
		return true
	}
	return '0' <= c && c <= '9'
}

// isSpace reports the characters strings.TrimSpace or json.Compact may
// remove; every non-ASCII character counts, as a few of them are spaces.
func isSpace(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '\v', '\f', nonASCII:
		return true
	}
	return false
}

// matchFence advances a match of fencePrefix by one character.
func matchFence(matched int, c byte) int {
	switch {
	case c == fencePrefix[matched]:
		return matched + 1
	case c != '`':
		return 0
	case matched == 3:
		return 3
	}
	return 1
}

// decodeChar decodes the string character at b[i]: the character itself
// (nonASCII for anything at or above U+0080), how many body bytes it spans,
// and an upper bound on its UTF-8 length. ok is false for input that is not
// valid inside a JSON string.
func decodeChar(b []byte, i int) (c byte, width, size int, ok bool) {
	c = b[i]
	switch {
	case c < 0x20:
		return 0, 0, 0, false
	case c >= 0x80:
		return nonASCII, 1, 1, true
	case c != '\\':
		return c, 1, 1, true
	case i+1 >= len(b):
		return 0, 0, 0, false
	}
	switch e := b[i+1]; e {
	case '"', '\\', '/':
		return e, 2, 1, true
	case 'b':
		return '\b', 2, 1, true
	case 'f':
		return '\f', 2, 1, true
	case 'n':
		return '\n', 2, 1, true
	case 'r':
		return '\r', 2, 1, true
	case 't':
		return '\t', 2, 1, true
	case 'u':
		if i+6 > len(b) {
			return 0, 0, 0, false
		}
		r := 0
		for _, h := range b[i+2 : i+6] {
			v, ok := hexValue(h)
			if !ok {
				return 0, 0, 0, false
			}
			r = r<<4 | v
		}
		if r >= 0x80 {
			return nonASCII, 6, 3, true
		}
		return byte(r), 6, 1, true
	}
	return 0, 0, 0, false
}

func hexValue(h byte) (int, bool) {
	switch {
	case '0' <= h && h <= '9':
		return int(h - '0'), true
	case 'a' <= h && h <= 'f':
		return int(h-'a') + 10, true
	case 'A' <= h && h <= 'F':
		return int(h-'A') + 10, true
	}
	return 0, false
}

// skipString returns the index of the quote closing the string that opens at
// b[i], or -1 when there is none.
func skipString(b []byte, i int) int {
	for j := i + 1; j < len(b); j++ {
		switch c := b[j]; {
		case c == '"':
			return j
		case c == '\\':
			j++
		case c < 0x20:
			return -1
		}
	}
	return -1
}

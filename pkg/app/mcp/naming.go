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
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"unicode/utf8"

	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// maxExposedNameLength is what an MCP client will accept for a tool name.
const maxExposedNameLength = 64

// nameHashLength is the hex a truncated name carries, enough that two tools
// truncated to the same stem stay apart.
const nameHashLength = 8

// collisionSuffixLen is the hex appended when two servers genuinely expose one
// name. It stays off every other name: a client that stored those must not see
// them change because some other server happened to spell one tool the same way.
const collisionSuffixLen = 4

// resolveNames publishes the name tools/list and tools/call share. Two servers
// can spell different tools the same way — google's drive_list and
// google_drive's list are both google_drive_list — and then each takes a digest
// of the registry that serves it. A name nobody else serves is left as it was,
// so installing an unrelated server cannot rename it.
func resolveNames(candidates []binding, _ []*registrydomain.Registry) []binding {
	published, _ := resolveNamesSeen(candidates, nil)
	return published
}

// resolveNamesSeen publishes candidates. background is the rest of the upstream
// list: tools the toolkit will not publish. They take part in within-server
// prefix stripping, so hiding a sibling cannot point an existing name at a
// different tool. They do not count toward a cross-server suffix and they are
// not published.
func resolveNamesSeen(candidates, background []binding) (published, hidden []binding) {
	all := make([]binding, 0, len(background)+len(candidates))
	all = append(all, background...)
	all = append(all, candidates...)
	chosen := make([]exposedChoice, len(all))
	for i, b := range all {
		chosen[i] = chooseExposed(b.exposed, b.registry)
	}
	// A tool whose upstream name already started with the server slug is
	// published without a second copy of that slug. When that spelling is also
	// the name of another tool on the same server, the one that arrived
	// already prefixed keeps the doubled form and the other keeps the short one.
	restoreDoubledPrefix(chosen, all)

	nBack := len(background)
	count := make(map[string]int, len(candidates))
	for i := nBack; i < len(all); i++ {
		count[chosen[i].name]++
	}
	// fromSuffix marks a name produced by the collision digest. That binding is
	// the original owner of the spelling. A later plain name that copies it
	// (list_<that digest> on the other server) is not.
	out := make([]binding, len(candidates))
	fromSuffix := make([]bool, len(candidates))
	for i := range candidates {
		name := chosen[nBack+i].name
		if count[name] > 1 {
			name = disambiguateCollision(name, candidates[i].registry)
			fromSuffix[i] = true
		}
		out[i] = candidates[i]
		out[i].exposed = name
	}
	hidden = make([]binding, len(background))
	for i := range background {
		hidden[i] = background[i]
		hidden[i].exposed = chosen[i].name
	}
	return withholdCopiedNames(out, fromSuffix), hidden
}

// exposedChoice is one tool's published spelling before cross-server collisions
// are suffixed. stripped is set when a repeated server prefix was dropped;
// doubled is the spelling with that prefix kept, used only if stripped collides
// with another tool of the same server.
type exposedChoice struct {
	name     string
	doubled  string
	stripped bool
}

func chooseExposed(upstream string, reg *registrydomain.Registry) exposedChoice {
	slug := serverSlug(reg)
	plain := exposedName{name: upstream, server: slug}.String()
	if slug == "" || !hasSlugPrefix(upstream, slug) {
		return exposedChoice{name: plain}
	}
	doubled := exposedName{name: upstream, server: slug, keepPrefix: true}.String()
	return exposedChoice{name: plain, doubled: doubled, stripped: plain != doubled}
}

// restoreDoubledPrefix switches a stripped name to its doubled form when
// another tool of the same server publishes that stripped spelling, and keeps
// going while a doubled form lands on yet another tool of that server. One
// pass used to stop at the first collision, so x, clickup_x and
// clickup_clickup_x left two tools with one spelling and both were dropped.
// Each tool moves at most once, so the result is a unique name per upstream
// tool and does not depend on the order the tools were given.
func restoreDoubledPrefix(chosen []exposedChoice, named []binding) bool {
	stripped := false
	for _, c := range chosen {
		if c.stripped {
			stripped = true
			break
		}
	}
	if !stripped {
		return false
	}
	changed := false
	for range chosen {
		if !bumpStrippedCollision(chosen, named) {
			break
		}
		changed = true
	}
	return changed
}

type serverName struct {
	reg  *registrydomain.Registry
	name string
}

// bumpStrippedCollision moves every stripped tool whose current spelling is
// shared on its server to the doubled form. Tools that were not stripped keep
// the short spelling. It reports whether anything moved.
func bumpStrippedCollision(chosen []exposedChoice, named []binding) bool {
	hits := make(map[serverName]int, len(chosen))
	for i, c := range chosen {
		hits[serverName{reg: named[i].registry, name: c.name}]++
	}
	moved := false
	for i, c := range chosen {
		if !c.stripped || hits[serverName{reg: named[i].registry, name: c.name}] < 2 {
			continue
		}
		chosen[i].name = c.doubled
		chosen[i].stripped = false
		moved = true
	}
	return moved
}

// withholdCopiedNames drops a final name that more than one binding ended up
// with. The binding whose collision suffix produced the spelling stays; every
// other copy is withheld, so a server cannot publish list_<victim digest> and
// take the victim's name. When no single suffix owns the spelling, every copy
// is withheld. Order of the names that remain is the order they were given.
func withholdCopiedNames(named []binding, fromSuffix []bool) []binding {
	finalCount := make(map[string]int, len(named))
	ownerCount := make(map[string]int, len(named))
	for i, b := range named {
		finalCount[b.exposed]++
		if fromSuffix[i] {
			ownerCount[b.exposed]++
		}
	}
	out := make([]binding, 0, len(named))
	for i, b := range named {
		if finalCount[b.exposed] < 2 {
			out = append(out, b)
			continue
		}
		if fromSuffix[i] && ownerCount[b.exposed] == 1 {
			out = append(out, b)
		}
	}
	return out
}

func disambiguateCollision(base string, reg *registrydomain.Registry) string {
	suffix := "_" + registryDigest(reg, collisionSuffixLen)
	if len(base)+len(suffix) <= maxExposedNameLength {
		return base + suffix
	}
	return fitCollisionV2(serverSlug(reg), base, suffix)
}

// fitCollisionV2 keeps the server prefix and the tail of base, and puts the
// collision digest between them, so a name that no longer fits does not lose
// the action words at the end.
func fitCollisionV2(server, base, suffix string) string {
	hash := strings.TrimPrefix(suffix, "_")
	prefix, body := splitServerPrefix(server, base)
	room := maxExposedNameLength - len(prefix) - len(hash) - 1
	if room < 1 && server != "" && server != hashedSlug(server) {
		hashed := hashedSlug(server)
		rebuilt := hashed + "_" + body
		return fitCollisionV2(hashed, rebuilt, suffix)
	}
	if room < 1 {
		room = maxExposedNameLength - len(hash) - 1
		prefix = ""
		body = base
		if room < 1 {
			return suffix[len(suffix)-maxExposedNameLength:]
		}
	}
	return prefix + hash + "_" + suffixWithin(body, room)
}

// exposedName is a tool as the caller sees it: the server it came from, and
// the name that server gave it.
type exposedName struct {
	name       string
	server     string
	keepPrefix bool
}

func exposedNameFor(name string, reg *registrydomain.Registry) exposedName {
	return exposedName{name: name, server: serverSlug(reg)}
}

// String is the name the caller calls the tool by. An upstream name that
// already begins with "<slug>_" is published as that name, unless keepPrefix
// is set because another tool of the same server would otherwise take it. A
// name that still does not fit keeps the server prefix and equal shares of
// the tool's start and end, with the content hash between them.
func (e exposedName) String() string {
	server := e.server
	tool := e.name
	var full string
	switch {
	case server == "" || e.keepPrefix || !hasSlugPrefix(tool, server):
		if server == "" {
			full = tool
		} else {
			full = server + "_" + tool
		}
	default:
		full = withCanonicalSlugPrefix(tool, server)
	}
	if len(full) <= maxExposedNameLength {
		return full
	}
	return cutMiddleV2(server, full, contentSuffix(full), false)
}

// hasSlugPrefix reports whether tool begins with "<slug>_", ignoring case.
func hasSlugPrefix(tool, slug string) bool {
	if slug == "" {
		return false
	}
	prefix := slug + "_"
	return len(tool) >= len(prefix) && strings.EqualFold(tool[:len(prefix)], prefix)
}

// withCanonicalSlugPrefix returns tool unchanged when its slug prefix already
// matches byte for byte, and rewrites only that prefix when the case differs,
// so tools/call can find the server by the slug it knows.
func withCanonicalSlugPrefix(tool, slug string) string {
	prefix := slug + "_"
	if strings.HasPrefix(tool, prefix) {
		return tool
	}
	return prefix + tool[len(prefix):]
}

// cutMiddleV2 keeps server_ (when full starts with it) and cuts the tool from
// the middle, so action words at either end survive. rehashed stops a slug
// that still crowds the tool out from hashing itself again.
func cutMiddleV2(server, full, suffix string, rehashed bool) string {
	hash := strings.TrimPrefix(suffix, "_")
	prefix, body := splitServerPrefix(server, full)
	room := maxExposedNameLength - len(prefix) - len(hash) - 1
	if room < 1 && !rehashed && server != "" {
		hashed := hashedSlug(server)
		rebuilt := hashed + "_" + body
		if len(rebuilt) <= maxExposedNameLength {
			return rebuilt
		}
		return cutMiddleV2(hashed, rebuilt, suffix, true)
	}
	if room < 1 {
		room = maxExposedNameLength - len(hash) - 1
		if room < 1 {
			return suffix[len(suffix)-maxExposedNameLength:]
		}
		prefix = ""
		body = full
	}
	return joinMiddleCut(prefix, hash, body, room)
}

// joinMiddleCut publishes prefix + head + "_" + hash + "_" + tail. room is the
// bytes a one-separator tail would have had; both sides spend one of those
// bytes on the second underscore. The two sides take equal shares (the odd
// byte goes to the tail). Cuts stay on rune boundaries, and an underscore
// sitting against the hash is dropped — a tail that began with '_' used to
// publish a double underscore.
func joinMiddleCut(prefix, hash, body string, room int) string {
	if room < 1 || body == "" {
		return prefix + hash
	}
	var head, tail string
	shared := room - 1
	if shared < 2 {
		tail = strings.TrimLeft(suffixWithin(body, room), "_")
	} else {
		head = prefixWithin(body, shared/2)
		tail = suffixWithin(body, shared-shared/2)
		if strings.HasSuffix(prefix, "_") {
			head = strings.TrimLeft(head, "_")
		}
		head = strings.TrimRight(head, "_")
		tail = strings.TrimLeft(tail, "_")
	}
	out := prefix + head
	if head != "" {
		out += "_"
	}
	out += hash
	if tail != "" {
		out += "_" + tail
	}
	return out
}

// prefixWithin returns the head of s that fits in room bytes and ends on a
// rune boundary. A byte slice of that length can end on the first byte of a
// rune, and an MCP client would then be handed a name that is not UTF-8.
func prefixWithin(s string, room int) string {
	if room < 1 || s == "" {
		return ""
	}
	if len(s) <= room {
		return s
	}
	end := room
	for end > 0 && !utf8.RuneStart(s[end]) {
		end--
	}
	return s[:end]
}

// suffixWithin returns the tail of s that fits in room bytes and starts on a
// rune boundary. A byte slice of that length can begin on a continuation
// byte, and an MCP client would then be handed a name that is not UTF-8.
func suffixWithin(s string, room int) string {
	if room < 1 || s == "" {
		return ""
	}
	if len(s) <= room {
		return s
	}
	start := len(s) - room
	for start < len(s) && !utf8.RuneStart(s[start]) {
		start++
	}
	if start >= len(s) {
		return ""
	}
	return s[start:]
}

func splitServerPrefix(server, full string) (prefix, body string) {
	if server == "" {
		return "", full
	}
	want := server + "_"
	if len(full) >= len(want) && strings.EqualFold(full[:len(want)], want) {
		return full[:len(want)], full[len(want):]
	}
	return "", full
}

func contentSuffix(full string) string {
	digest := sha256.Sum256([]byte(full))
	return "_" + hex.EncodeToString(digest[:nameHashLength/2])
}

// hashedSlug is the server prefix used when the slug itself is too long to
// leave a tool character. It is a property of the slug alone, so every tool on
// that server shares it and a call can find the server without being shown the
// list first.
func hashedSlug(slug string) string {
	digest := sha256.Sum256([]byte(slug))
	return hex.EncodeToString(digest[:nameHashLength/2])
}

// slugCrowdsOutTool reports that reserving the content-hash suffix would leave
// the tool with nothing, which is when String replaces the slug with hashedSlug.
func slugCrowdsOutTool(slug string) bool {
	return maxExposedNameLength-len(slug)-1-(1+nameHashLength) < 1
}

// serverSlug names the server a tool came from, in a way that survives
// everything but the server being replaced.
//
// The catalog code is the one stable, unique identifier a server has: an
// admin's rename does not touch it, and no two catalog entries share one. The
// leading reverse-DNS label and a trailing "/mcp" carry no information and only
// cost the reader, so com.notion/mcp reads as "notion" and
// com.google_cloud/developerknowledge as "google_cloud_developerknowledge".
//
// Several instances of one code — a Snowflake schema per team — share it, so
// each takes a short digest of its own registry id. That covers a Store
// principal's per-install clones that carry no config too: two configured
// instances of a server without URL variables, both installed, would otherwise
// serve every tool twice under one name. A registry wired by hand carries no
// code at all and takes the digest alone: opaque, but the price of having
// nothing stable to read.
func serverSlug(reg *registrydomain.Registry) string {
	if reg == nil {
		return ""
	}
	code := ""
	if reg.MCPTarget != nil {
		code = strings.TrimSpace(reg.MCPTarget.Code)
	}
	slug := slugFromCatalogCode(code)
	if slug == "" {
		return "s" + registryDigest(reg, 8)
	}
	// The digest is added only when this registry is one of several active
	// instances of the code (its id differs from the shelf it clones). A
	// single configured instance keeps the readable slug.
	if !reg.InstanceOf.IsNil() && reg.ID != reg.InstanceOf {
		return slug + "_" + registryDigest(reg, 6)
	}
	return slug
}

// legacyExposedName is the spelling v0.66.0 published for local. local is the
// toolkit ExposeAs when one was set, and the upstream name otherwise: that
// release prefixed whichever of those it was about to publish. The server slug
// is always in front, a 6-char digest marks every configured instance, and an
// overlong name is cut at the tail. Resolve still accepts the result, so a
// client that listed tools before the v2 names keeps calling them, and pods on
// the old release and the new one answer the same call during a rollout.
func legacyExposedName(local string, reg *registrydomain.Registry) string {
	server := legacyServerSlug(reg)
	full := server + "_" + local
	if server == "" {
		full = local
	}
	if len(full) <= maxExposedNameLength {
		return full
	}
	suffix := contentSuffix(full)
	keep := maxExposedNameLength - len(server) - 1 - len(suffix)
	if keep < 1 {
		return full[:maxExposedNameLength-len(suffix)] + suffix
	}
	return server + "_" + local[:keep] + suffix
}

func legacyServerSlug(reg *registrydomain.Registry) string {
	if reg == nil || reg.MCPTarget == nil || len(reg.MCPTarget.InstanceConfig) == 0 {
		return serverSlug(reg)
	}
	slug := slugFromCatalogCode(reg.MCPTarget.Code)
	if slug == "" {
		return serverSlug(reg)
	}
	return slug + "_" + registryDigest(reg, 6)
}

// promptName is the spelling prompts keep: <server>_<prompt>. A repeated
// server prefix is not dropped the way a tool name is, and a name that does
// not fit loses the tail of the prompt to the content hash.
func promptName(name string, reg *registrydomain.Registry) string {
	server := serverSlug(reg)
	full := server + "_" + name
	if server == "" {
		full = name
	}
	if len(full) <= maxExposedNameLength {
		return full
	}
	suffix := contentSuffix(full)
	keep := maxExposedNameLength - len(server) - 1 - len(suffix)
	if keep < 1 && server != "" {
		server = hashedSlug(server)
		full = server + "_" + name
		if len(full) <= maxExposedNameLength {
			return full
		}
		suffix = contentSuffix(full)
		keep = maxExposedNameLength - len(server) - 1 - len(suffix)
	}
	if keep < 1 {
		return full[:maxExposedNameLength-len(suffix)] + suffix
	}
	return server + "_" + name[:keep] + suffix
}

func registryDigest(reg *registrydomain.Registry, n int) string {
	sum := sha256.Sum256([]byte(reg.ID.String()))
	return hex.EncodeToString(sum[:])[:n]
}

// slugFromCatalogCode turns a catalog code into the readable part of a tool
// name. Empty for a code that leaves nothing behind.
func slugFromCatalogCode(code string) string {
	code = strings.ToLower(strings.TrimSpace(code))
	if code == "" {
		return ""
	}
	code = strings.TrimSuffix(code, "/mcp")
	// The reverse-DNS label ("com.", "io.", "ai.") is the same for hundreds of
	// entries; what follows it is the name. Everything after the first label is
	// kept, because com.google_cloud/logging and com.google_cloud/monitoring are
	// different servers.
	if head, rest, found := strings.Cut(code, "."); found && head != "" && rest != "" {
		code = rest
	}
	var b strings.Builder
	lastUnderscore := false
	for _, r := range code {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			lastUnderscore = false
		case !lastUnderscore && b.Len() > 0:
			b.WriteByte('_')
			lastUnderscore = true
		}
	}
	return strings.Trim(b.String(), "_")
}

// registriesForExposedName returns every registry whose server prefix fits an
// exposed tool name. That name is "<server>_<tool>", so a tools/call does not
// dial a server that does not fit — dialing those minted a connect ticket for
// a server the call does not target.
//
// More than one prefix can fit. google_drive_list is google's drive_list and
// google_drive's list, and keeping only the longest used to make the shorter
// server's tool unreachable and answer with the longer server's consent. Every
// fit is returned; the caller keeps the one that serves the exact name.
func registriesForExposedName(registries []*registrydomain.Registry, name string) []*registrydomain.Registry {
	var owners []*registrydomain.Registry
	for _, reg := range registries {
		if matchedPrefixLen(reg, name) == 0 {
			continue
		}
		owners = append(owners, reg)
	}
	return owners
}

// matchedPrefixLen is the longest server prefix of reg that fits name, or 0
// when none does. A slug long enough to have been hashed also matches that hash.
func matchedPrefixLen(reg *registrydomain.Registry, name string) int {
	best := 0
	for _, prefix := range exposurePrefixes(serverSlug(reg)) {
		if strings.HasPrefix(name, prefix) && len(prefix) > best {
			best = len(prefix)
		}
	}
	return best
}

func exposurePrefixes(slug string) []string {
	if slug == "" {
		return nil
	}
	prefixes := []string{slug + "_"}
	if slugCrowdsOutTool(slug) {
		hashed := hashedSlug(slug) + "_"
		if hashed != prefixes[0] {
			prefixes = append(prefixes, hashed)
		}
	}
	return prefixes
}

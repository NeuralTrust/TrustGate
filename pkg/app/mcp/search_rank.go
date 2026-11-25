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
	"math"
	"sort"
	"strings"
	"unicode"
)

// Ranking for trustgate_search.
//
// The ranking only orders. It never decides what exists: a listing without a
// query returns every tool, and a call by exact name reaches a tool whether or
// not a search ever returned it. What a ranking bug costs is a tool further
// down the page, never a tool the caller cannot get to.
//
// It is BM25 over a handful of fields, weighted so the words a tool is named
// by count for more than the words its description uses. The description is
// the one field an upstream writes freely, so it is cut before it is indexed
// and weighs the least: a server cannot buy the top of every search by
// stuffing its descriptions.
//
// On top of the words, the verb a request asks with is matched against the
// verb a tool is named with (search_intent.go), and a tool whose server the
// request names counts for more. testdata/search_eval.json measures all of it
// against requests as people write them (search_eval_test.go).

const (
	bm25K1 = 1.2
	bm25B  = 0.75

	weightName        = 3.0
	weightTitle       = 2.0
	weightServer      = 1.5
	weightDescription = 1.0
	weightParam       = 1.0

	// maxIndexedDescription is how much of a description is indexed.
	maxIndexedDescription = 300

	// synonymWeight is how much a word matched through a synonym counts
	// against the word the caller wrote.
	synonymWeight = 0.6
	// impliedWeight is how much a word reached through impliedWords counts.
	impliedWeight = 0.5

	// serverMentionBoost is how much more a tool counts when the query names
	// its server: a request that says where is rarely about anywhere else.
	serverMentionBoost = 1.5

	// exactNameBonus puts a tool asked for by its exact name first.
	exactNameBonus = 100.0
	// nameContainsBonus favours a tool whose name holds the whole query.
	nameContainsBonus = 2.0
)

// searchDoc is one tool as the ranking sees it.
type searchDoc struct {
	Name        string
	Title       string
	Server      string
	Code        string
	Description string
	Params      []string
}

// rankedDoc is a document's position in a ranking.
type rankedDoc struct {
	Index int
	Score float64
}

// synonymGroups are words a person and a tool use for the same thing. A query
// word also matches the other words of its group, at synonymWeight. The groups
// stay narrow on purpose: a broad one ranks the wrong tool first. Words are
// written as people write them; they are normalized like any other word, so a
// plural or an accent is matched too.
var synonymGroups = [][]string{
	{"issue", "ticket", "bug", "incidencia", "incidencias"},
	{"pr", "pull"},
	{"email", "mail", "gmail", "correo", "correos"},
	{"message", "msg", "mensaje", "chat"},
	{"doc", "document", "documento"},
	{"repo", "repository", "repositorio"},
	{"comment", "comentario", "comentar"},
	// "add" is left out: it is how a comment or a member is added at least as
	// often as how something new is created.
	{"create", "new", "crear", "nuevo", "nueva"},
	{"delete", "remove", "borrar", "eliminar"},
	{"list", "listar"},
	{"search", "find", "buscar", "query"},
	{"send", "post", "enviar"},
	{"file", "archivo", "fichero"},
	{"meeting", "event", "reunion", "evento"},
	{"calendar", "calendario"},
	{"task", "todo", "tarea"},
	{"user", "member", "usuario", "person"},
	{"update", "edit", "modify", "change", "actualizar", "editar", "cambiar"},
	{"move", "mover"},
	{"get", "fetch", "read", "obtener", "leer"},
	{"channel", "canal"},
	{"page", "pagina"},
	{"spreadsheet", "sheet", "hoja"},
	{"record", "row", "registro", "fila", "entry"},
	{"refund", "reembolso", "devolucion"},
	{"invoice", "factura"},
	{"customer", "cliente", "client"},
	{"contact", "contacto"},
	{"deployment", "deploy", "despliegue"},
	{"release", "version", "publicada", "publicado"},
	{"project", "proyecto"},
	{"team", "equipo"},
	{"transcript", "transcripcion"},
	{"draft", "borrador", "redactar"},
	{"oncall", "guardia"},
	{"incident", "incidente", "outage", "broke", "broken"},
	{"error", "errores", "exception", "crash", "failure", "fallo", "broke", "broken"},
	{"payment", "pago", "pagos"},
	{"invitation", "invite", "invitacion"},
	{"accept", "rsvp", "aceptar"},
	{"acknowledge", "ack"},
	{"slot", "availability", "free", "hueco"},
	{"note", "nota", "notas"},
	{"today", "hoy"},
	{"tomorrow", "manana"},
}

var synonyms = func() map[string][]string {
	out := make(map[string][]string)
	for _, group := range synonymGroups {
		words := make([]string, 0, len(group))
		for _, word := range group {
			if w := normalizeToken(word); w != "" {
				words = append(words, w)
			}
		}
		for _, word := range words {
			for _, other := range words {
				if other != word && !containsWord(out[word], other) {
					out[word] = append(out[word], other)
				}
			}
		}
	}
	return out
}()

func containsWord(words []string, word string) bool {
	for _, w := range words {
		if w == word {
			return true
		}
	}
	return false
}

// impliedWords are what a tool is likely named for a word a request uses. They
// go one way only: moving a meeting is updating it, but updating a page is not
// moving it. A word reached this way counts at impliedWeight.
var impliedWords = func() map[string][]string {
	out := make(map[string][]string)
	for _, rule := range []struct{ words, implied string }{
		{"move mover reschedule reprogramar mark marcar complete completar finish", "update"},
		{"move", "transition"},
		{"cancel cancelar", "delete"},
		{"schedule book agendar programar", "create"},
		{"create new crear nuevo nueva add", "save"},
		{"open abrir write escribir add anadir agregar hacer make", "create"},
		{"reply responder contestar", "comment send"},
		{"acknowledge ack resolve resolver", "manage update"},
		{"accept aceptar decline rechazar rsvp", "respond"},
		{"tell notify avisar notificar inform ping", "send message"},
		{"show see view ver mostrar muestra", "list get"},
		{"look", "get search"},
	} {
		for _, word := range splitWords(rule.words) {
			word = normalizeToken(word)
			for _, target := range splitWords(rule.implied) {
				if !containsWord(out[word], target) {
					out[word] = append(out[word], target)
				}
			}
		}
	}
	return out
}()

// stopwords are words that say nothing about which tool is meant.
var stopwords = map[string]struct{}{
	"the": {}, "an": {}, "to": {}, "of": {}, "for": {}, "and": {}, "or": {}, "in": {}, "on": {},
	"with": {}, "by": {}, "my": {}, "me": {}, "it": {}, "is": {}, "from": {}, "this": {}, "that": {},
	"de": {}, "la": {}, "el": {}, "los": {}, "las": {}, "un": {}, "una": {}, "en": {}, "para": {},
	"con": {}, "por": {}, "mi": {}, "mis": {}, "que": {}, "del": {}, "al": {}, "se": {}, "lo": {},
}

// searchTokens splits text into the words the ranking compares: on anything
// that is not a letter or a digit, on snake_case and on camelCase, lowercased,
// with plurals folded and stopwords dropped.
func searchTokens(text string) []string {
	var tokens []string
	for _, word := range searchWords(text) {
		if _, stop := stopwords[word]; !stop {
			tokens = append(tokens, word)
		}
	}
	return tokens
}

// searchWords splits text like searchTokens and keeps the stopwords: what a
// request asks for can hang on one ("what", "qué", "who").
func searchWords(text string) []string {
	var tokens []string
	var current []rune
	flush := func() {
		if len(current) == 0 {
			return
		}
		word := normalizeToken(string(current))
		current = current[:0]
		if word == "" {
			return
		}
		tokens = append(tokens, word)
	}
	runes := []rune(text)
	for i, r := range runes {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			flush()
			continue
		}
		// A capital after a lower-case letter starts a word: listIssues.
		if i > 0 && unicode.IsUpper(r) && unicode.IsLower(runes[i-1]) {
			flush()
		}
		current = append(current, r)
	}
	flush()
	return tokens
}

func normalizeToken(word string) string {
	word = strings.ToLower(foldAccents(word))
	if len([]rune(word)) < 2 && !isDigits(word) {
		return ""
	}
	switch {
	// Spanish plurals of words in -ión: reuniones, acciones, versiones.
	case len(word) > 6 && strings.HasSuffix(word, "iones"):
		return strings.TrimSuffix(word, "es")
	case len(word) > 4 && strings.HasSuffix(word, "ies"):
		return strings.TrimSuffix(word, "ies") + "y"
	case len(word) > 3 && strings.HasSuffix(word, "s") && !strings.HasSuffix(word, "ss"):
		return strings.TrimSuffix(word, "s")
	}
	return word
}

func isDigits(word string) bool {
	if word == "" {
		return false
	}
	for _, r := range word {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

var accentFolder = strings.NewReplacer(
	"á", "a", "é", "e", "í", "i", "ó", "o", "ú", "u", "ü", "u", "ñ", "n",
	"Á", "A", "É", "E", "Í", "I", "Ó", "O", "Ú", "U", "Ü", "U", "Ñ", "N",
)

func foldAccents(word string) string {
	return accentFolder.Replace(word)
}

// Each field is scored on its own and saturates on its own (BM25F): many
// mentions of a word in one field count for little more than one, so a long or
// repetitive field cannot outweigh a name. The description and the parameter
// names count each distinct word once, and only the first
// maxDescriptionWords of them.
const maxDescriptionWords = 40

type searchField int

const (
	fieldName searchField = iota
	fieldTitle
	fieldServer
	fieldDescription
	fieldParams
	fieldCount
)

var fieldWeights = [fieldCount]float64{
	fieldName:        weightName,
	fieldTitle:       weightTitle,
	fieldServer:      weightServer,
	fieldDescription: weightDescription,
	fieldParams:      weightParam,
}

type indexedDoc struct {
	terms  [fieldCount]map[string]float64
	length [fieldCount]float64
	name   string
	action action
}

func indexSearchDoc(doc searchDoc) indexedDoc {
	out := indexedDoc{name: strings.ToLower(doc.Name)}
	for f := range out.terms {
		out.terms[f] = make(map[string]float64)
	}
	addAll := func(field searchField, text string) {
		for _, token := range searchTokens(text) {
			out.terms[field][token]++
			out.length[field]++
		}
	}
	addDistinct := func(field searchField, text string, limit int) {
		for _, token := range searchTokens(text) {
			if _, seen := out.terms[field][token]; seen {
				continue
			}
			if limit > 0 && len(out.terms[field]) >= limit {
				return
			}
			out.terms[field][token] = 1
			out.length[field]++
		}
	}
	addAll(fieldName, doc.Name)
	addAll(fieldTitle, doc.Title)
	addAll(fieldServer, doc.Server+" "+doc.Code)
	addDistinct(fieldDescription, truncateRunes(doc.Description, maxIndexedDescription), maxDescriptionWords)
	addDistinct(fieldParams, strings.Join(doc.Params, " "), 0)
	out.action = toolAction(searchWords(doc.Name), out.terms[fieldServer])
	return out
}

func (d indexedDoc) has(word string) bool {
	for f := range d.terms {
		if d.terms[f][word] > 0 {
			return true
		}
	}
	return false
}

func truncateRunes(text string, limit int) string {
	runes := []rune(text)
	if len(runes) <= limit {
		return text
	}
	return string(runes[:limit])
}

// queryTerm is one word the ranking looks for, with how much a match counts.
type queryTerm struct {
	word   string
	weight float64
}

func queryTerms(query string) []queryTerm {
	seen := make(map[string]float64)
	var order []string
	add := func(word string, weight float64) {
		if prev, ok := seen[word]; ok {
			if weight > prev {
				seen[word] = weight
			}
			return
		}
		seen[word] = weight
		order = append(order, word)
	}
	words := searchWords(query)
	for _, word := range words {
		if _, stop := stopwords[word]; stop {
			continue
		}
		add(word, 1)
		for _, other := range synonyms[word] {
			add(other, synonymWeight)
		}
		for _, other := range impliedWords[word] {
			add(other, impliedWeight)
		}
	}
	// Two words a tool writes as one: "on call" is oncall, "to do" is todo.
	// The joined word only counts where a tool uses it.
	for i := 0; i+1 < len(words); i++ {
		joined := normalizeToken(words[i] + words[i+1])
		add(joined, 1)
		for _, other := range synonyms[joined] {
			add(other, synonymWeight)
		}
	}
	out := make([]queryTerm, 0, len(order))
	for _, word := range order {
		out = append(out, queryTerm{word: word, weight: seen[word]})
	}
	return out
}

// mentionsServer reports whether the query names the document's server, by a
// word of its name or code: "in linear", "on my calendar", "en hubspot".
func mentionsServer(words []string, doc indexedDoc) bool {
	for _, word := range words {
		if doc.terms[fieldServer][word] > 0 {
			return true
		}
	}
	return false
}

// rankSearchDocs orders the documents a query matches, best first. A document
// that matches nothing is left out. Ties keep the documents' own order, so the
// same query over the same tools always answers the same way.
func rankSearchDocs(query string, docs []searchDoc) []rankedDoc {
	terms := queryTerms(query)
	if len(terms) == 0 || len(docs) == 0 {
		return nil
	}
	indexed := make([]indexedDoc, len(docs))
	var totals [fieldCount]float64
	df := make(map[string]int)
	for i, doc := range docs {
		indexed[i] = indexSearchDoc(doc)
		for f := range totals {
			totals[f] += indexed[i].length[f]
		}
	}
	for _, term := range terms {
		for i := range indexed {
			if indexed[i].has(term.word) {
				df[term.word]++
			}
		}
	}
	n := float64(len(docs))
	var avg [fieldCount]float64
	for f := range avg {
		avg[f] = totals[f] / n
		if avg[f] == 0 {
			avg[f] = 1
		}
	}
	exact := strings.ToLower(strings.TrimSpace(query))
	joined := strings.Join(searchTokens(query), "_")
	asked := requestAction(searchWords(query))
	words := searchTokens(query)

	var out []rankedDoc
	for i, doc := range indexed {
		var score float64
		for _, term := range terms {
			if df[term.word] == 0 {
				continue
			}
			idf := math.Log(1 + (n-float64(df[term.word])+0.5)/(float64(df[term.word])+0.5))
			var fields float64
			for f := searchField(0); f < fieldCount; f++ {
				tf := doc.terms[f][term.word]
				if tf == 0 {
					continue
				}
				norm := tf * (bm25K1 + 1) / (tf + bm25K1*(1-bm25B+bm25B*doc.length[f]/avg[f]))
				fields += fieldWeights[f] * norm
			}
			score += term.weight * idf * fields
		}
		if score == 0 {
			continue
		}
		score *= intentFactor(asked, doc.action)
		if mentionsServer(words, doc) {
			score *= serverMentionBoost
		}
		if exact != "" && doc.name == exact {
			score += exactNameBonus
		} else if joined != "" && strings.Contains(doc.name, joined) {
			score += nameContainsBonus
		}
		out = append(out, rankedDoc{Index: i, Score: score})
	}
	sort.SliceStable(out, func(a, b int) bool {
		return out[a].Score > out[b].Score
	})
	return out
}

// substringMatches is the ranking's fallback for a query nothing scored: the
// documents whose name or description holds one of the query's longer words.
// It is what the listing tools did before there was a ranking, so a query never
// finds less than it would have then.
func substringMatches(query string, docs []searchDoc) []rankedDoc {
	var words []string
	for _, word := range strings.FieldsFunc(strings.ToLower(foldAccents(query)), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	}) {
		if len([]rune(word)) >= 3 {
			words = append(words, word)
		}
	}
	if len(words) == 0 {
		return nil
	}
	var out []rankedDoc
	for i, doc := range docs {
		haystack := strings.ToLower(foldAccents(doc.Name + " " + doc.Title + " " + doc.Description))
		for _, word := range words {
			if strings.Contains(haystack, word) {
				out = append(out, rankedDoc{Index: i, Score: 0})
				break
			}
		}
	}
	return out
}

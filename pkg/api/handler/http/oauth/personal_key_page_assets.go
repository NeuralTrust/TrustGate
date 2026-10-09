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

package oauth

import (
	"bytes"
	"encoding/json"
	"html/template"
	"strings"
	"unicode"

	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	"github.com/gofiber/fiber/v2"
)

// The key stays a placeholder in the snippets, as in the Portal: the secret is
// copied from its own box, never written into code that is copied around.
const (
	personalKeyPlaceholder = "<your-api-key>"
	personalKeyModel       = "<model>"
)

type personalKeySnippet struct {
	ID    string
	Label string
	// Code is what Copy puts on the clipboard; Lines is how it is drawn.
	Code  string
	Lines []snippetLine
}

// snippetLine is one numbered line of a snippet, cut into coloured tokens.
type snippetLine struct {
	N      int
	Tokens []snippetToken
}

// snippetToken is a run of a line in one colour. Kind is a CSS suffix: key,
// str, kw, com, ph (a value the reader replaces), or empty for plain text.
type snippetToken struct {
	Kind string
	Text string
}

// snippetPlaceholders are the values a reader fills in, drawn as fields the
// way the console's code blocks draw them.
var snippetPlaceholders = []string{personalKeyPlaceholder, personalKeyModel}

var snippetKeywords = map[string]bool{
	"from": true, "import": true, "while": true, "for": true, "in": true,
	"if": true, "else": true, "return": true, "def": true, "True": true, "False": true, "None": true,
}

// highlightSnippet colours Python and JSON the way the console's code blocks
// do: comments, keywords, strings, and a string followed by a colon as a key.
func highlightSnippet(code string) []snippetLine {
	raw := strings.Split(strings.TrimSuffix(code, "\n"), "\n")
	out := make([]snippetLine, 0, len(raw))
	for i, line := range raw {
		out = append(out, snippetLine{N: i + 1, Tokens: splitPlaceholders(highlightLine(line))})
	}
	return out
}

func highlightLine(line string) []snippetToken {
	var tokens []snippetToken
	var plain strings.Builder
	flush := func() {
		if plain.Len() > 0 {
			tokens = append(tokens, snippetToken{Text: plain.String()})
			plain.Reset()
		}
	}
	runes := []rune(line)
	for i := 0; i < len(runes); {
		switch r := runes[i]; {
		case r == '#':
			flush()
			tokens = append(tokens, snippetToken{Kind: "com", Text: string(runes[i:])})
			return tokens
		case r == '"':
			end := i + 1
			for end < len(runes) && runes[end] != '"' {
				if runes[end] == '\\' {
					end++
				}
				end++
			}
			if end < len(runes) {
				end++
			}
			kind := "str"
			if rest := strings.TrimLeft(string(runes[end:]), " "); strings.HasPrefix(rest, ":") {
				kind = "key"
			}
			flush()
			tokens = append(tokens, snippetToken{Kind: kind, Text: string(runes[i:end])})
			i = end
		case unicode.IsLetter(r) || r == '_':
			end := i
			for end < len(runes) && (unicode.IsLetter(runes[end]) || unicode.IsDigit(runes[end]) || runes[end] == '_') {
				end++
			}
			if word := string(runes[i:end]); snippetKeywords[word] {
				flush()
				tokens = append(tokens, snippetToken{Kind: "kw", Text: word})
			} else {
				plain.WriteString(word)
			}
			i = end
		default:
			plain.WriteRune(r)
			i++
		}
	}
	flush()
	return tokens
}

// splitPlaceholders cuts the reader's values out of the tokens around them, so
// they are drawn as fields whatever colour surrounds them.
func splitPlaceholders(tokens []snippetToken) []snippetToken {
	out := make([]snippetToken, 0, len(tokens))
	for _, tok := range tokens {
		rest := tok.Text
		for rest != "" {
			at, which := -1, ""
			for _, ph := range snippetPlaceholders {
				if idx := strings.Index(rest, ph); idx >= 0 && (at < 0 || idx < at) {
					at, which = idx, ph
				}
			}
			if at < 0 {
				out = append(out, snippetToken{Kind: tok.Kind, Text: rest})
				break
			}
			if at > 0 {
				out = append(out, snippetToken{Kind: tok.Kind, Text: rest[:at]})
			}
			out = append(out, snippetToken{Kind: "ph", Text: which})
			rest = rest[at+len(which):]
		}
	}
	return out
}

// personalKeySnippets are the Portal's three ways to use the key: the
// TrustGate SDK (tools and models), any OpenAI-compatible SDK (models), and an
// MCP client (tools).
func personalKeySnippets(mcpURL, llmURL string) []personalKeySnippet {
	sdk := []string{"# pip install trustgate-sdk openai", "from openai import OpenAI", "from trustgate import ToolFormat, TrustGateUser", ""}
	if mcpURL != "" {
		sdk = append(sdk, `me = TrustGateUser("`+mcpURL+`", api_key="`+personalKeyPlaceholder+`")`)
	} else {
		sdk = append(sdk, `me = TrustGateUser(api_key="`+personalKeyPlaceholder+`")`)
	}
	sdk = append(sdk, "toolkit = me.connect().toolkit(ToolFormat.OPENAI_RESPONSES)  # your MCP tools")
	if llmURL != "" {
		sdk = append(sdk,
			"llm = me.llm()  # your models",
			"client = OpenAI(base_url=llm.base_url, api_key=llm.api_key)",
			"",
			`res = client.responses.create(model="`+personalKeyModel+`", tools=toolkit.tools, input="What can you do with my tools?")`,
			`while any(item.type == "function_call" for item in res.output):`,
			`    res = client.responses.create(model="`+personalKeyModel+`", tools=toolkit.tools, input=toolkit.execute(res.output), previous_response_id=res.id)`,
			"print(res.output_text)",
		)
	}
	out := []personalKeySnippet{{ID: "sdk", Label: "TrustGate SDK", Code: strings.Join(sdk, "\n")}}
	if llmURL != "" {
		out = append(out, personalKeySnippet{ID: "openai", Label: "OpenAI SDK", Code: strings.Join([]string{
			"# pip install openai",
			"from openai import OpenAI",
			"",
			`client = OpenAI(base_url="` + llmURL + `", api_key="` + personalKeyPlaceholder + `")`,
			`res = client.responses.create(model="` + personalKeyModel + `", input="Hello")`,
			"print(res.output_text)",
		}, "\n")})
	}
	// Written as the client reads it: url first, and the placeholder as typed,
	// not escaped the way encoding/json escapes <> for HTML.
	var mcp bytes.Buffer
	enc := json.NewEncoder(&mcp)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	_ = enc.Encode(map[string]any{"mcpServers": map[string]any{"trustgate-store": struct {
		URL     string            `json:"url"`
		Headers map[string]string `json:"headers"`
	}{URL: mcpURL, Headers: map[string]string{"Authorization": "Bearer " + personalKeyPlaceholder}}}})
	out = append(out, personalKeySnippet{ID: "mcp", Label: "MCP client", Code: strings.TrimSuffix(mcp.String(), "\n")})
	for i := range out {
		out[i].Lines = highlightSnippet(out[i].Code)
	}
	return out
}

type personalKeyPageView struct {
	Email       string
	HasKey      bool
	Masked      string
	Expiry      string
	Expired     bool
	Secret      string
	Revoked     bool
	Done        bool
	Unavailable string
	Notice      string
	CSRF        string
	FormAction  string
	Models      bool
	Snippets    []personalKeySnippet
}

func renderPersonalKeyPage(c *fiber.Ctx, view *appoauth.PersonalKeyView) error {
	data := personalKeyPageView{
		Email:       view.Email,
		Secret:      view.Secret,
		Revoked:     view.Revoked,
		Done:        view.Done,
		Unavailable: view.Unavailable,
		Notice:      view.Notice,
		CSRF:        view.CSRF,
		FormAction:  c.OriginalURL(),
		Models:      view.LLMURL != "",
		Snippets:    personalKeySnippets(view.MCPURL, view.LLMURL),
	}
	if view.Key != nil && !view.Revoked {
		data.HasKey = true
		data.Masked = view.Key.Prefix + "…" + view.Key.Suffix
		data.Expired = view.Key.Expired
		if view.Key.ExpiresAt != nil {
			data.Expiry = view.Key.ExpiresAt.UTC().Format("2 Jan 2006")
		}
	}
	return renderHTML(c, personalKeyPageTmpl, data)
}

type personalKeyProblem struct {
	Title  string
	Body   string
	Signed string
}

func renderPersonalKeyProblem(c *fiber.Ctx, status int, problem personalKeyProblem) error {
	var buf bytes.Buffer
	if err := personalKeyProblemTmpl.Execute(&buf, problem); err != nil {
		return err
	}
	c.Set(fiber.HeaderContentType, fiber.MIMETextHTMLCharsetUTF8)
	c.Set(fiber.HeaderCacheControl, "no-store, must-revalidate")
	return c.Status(status).Send(buf.Bytes())
}

const personalKeyCSS = `
.card.wide{max-width:720px}
.secret{display:flex;align-items:center;gap:8px;margin:16px 0 8px;padding:10px 12px;
  border:1px solid var(--stroke);border-radius:var(--radius-md);background:var(--bg-surface-hover)}
.secret code{flex:1;min-width:0;overflow-wrap:anywhere;border:0;background:transparent;padding:0;font-size:.8125rem}
.keyline{display:flex;align-items:center;justify-content:space-between;gap:12px;margin:8px 0 20px;
  padding:12px 14px;border:1px solid var(--stroke);border-radius:var(--radius-md)}
.keyline .meta{color:var(--fg-muted);font-size:.75rem;line-height:1rem;margin-top:4px}
.actions{display:flex;gap:8px;flex-wrap:wrap}
.actions form{margin:0}
.note{color:var(--fg-muted);font-size:.8125rem;line-height:1.25rem;margin:8px 0 0}
.usage{margin-top:24px}
.usage h2{font-size:.875rem;line-height:1.25rem;font-weight:600;margin:0 0 8px;color:var(--fg-title)}
.snip{display:flex;flex-direction:column;gap:8px;min-width:0;padding:12px;
  border:1px solid var(--stroke);border-radius:var(--radius-md);background:var(--bg-surface-hover)}
.snip-head{display:flex;align-items:center;justify-content:space-between;gap:12px}
.snip-tabs{display:flex;gap:16px;min-width:0;overflow-x:auto;scrollbar-width:none}
.snip-tab{appearance:none;height:32px;padding:0;border:0;border-bottom:2px solid transparent;background:transparent;
  font:500 12px/1 var(--font-sans);color:var(--fg-muted);white-space:nowrap;cursor:pointer}
.snip-tab:hover{color:var(--fg-default)}
.snip-tab[aria-selected="true"]{color:var(--fg-title);border-bottom-color:var(--brand)}
.snip-copy{flex-shrink:0;font-size:12px}
.snip pre{margin:0;overflow:auto;color:var(--fg-secondary)}
.snip pre code{display:table;min-width:100%;padding:0;border:0;border-radius:0;background:transparent;
  font:400 13px/22px var(--font-mono);color:inherit}
.snip .ln{display:table-row}
.snip .n{display:table-cell;padding-right:16px;text-align:right;color:var(--fg-disabled);user-select:none}
.snip .t{display:table-cell;padding-right:12px;white-space:pre}
.tk-key{color:#9053ff}.tk-str{color:#009b66}.tk-kw{color:#f58f57}.tk-com{color:var(--fg-muted)}
.tk-ph{border-radius:3px;padding:0 2px;background:rgb(255 222 19 / .28);color:#7a5c00;font-weight:500}
.flash.ok{background:var(--badge-green-bg);color:var(--badge-green);border-color:transparent}
`

var personalKeyPageTmpl = template.Must(template.New("personal-key").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
` + pageFonts + `
<title>Personal key - NeuralTrust TrustGate</title><style>` + pageCSS + personalKeyCSS + `</style></head>
<body class="dotted"><div class="card wide">` + brandHeader + `
<h1>Your personal key</h1>
<p class="sub">One key for your Store tools{{if .Models}} and your models{{end}}, from code: the TrustGate SDK, {{if .Models}}any OpenAI-compatible SDK, {{end}}or an MCP client. It runs as you{{if .Email}} (<strong>{{.Email}}</strong>){{end}}, with what Access grants you.</p>
{{if .Unavailable}}<div class="flash" role="status">{{.Unavailable}}</div>{{end}}
{{if .Notice}}<div class="flash" role="status">{{.Notice}}</div>{{end}}
{{if .Secret}}
<div class="flash ok" role="status">Copy your key now. It is shown once and cannot be shown again.</div>
<div class="secret"><code id="secret">{{.Secret}}</code><button class="btn secondary" type="button" id="copy">Copy</button></div>
<p class="note">{{if .Expiry}}It expires on {{.Expiry}}. {{end}}Keep it like a password: anyone holding it acts as you.{{if .Models}} Your models may take a few seconds to reach it.{{end}}</p>
{{else if .Revoked}}
<div class="flash ok" role="status">Your personal key is revoked. Anything using it stops working now.</div>
{{else if .HasKey}}
<div class="keyline"><div><code>{{.Masked}}</code><div class="meta">{{if .Expired}}Expired{{else if .Expiry}}Expires {{.Expiry}}{{end}}</div></div></div>
{{if not .Done}}<div class="actions">
  <form method="post" action="{{.FormAction}}"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="action" value="rotate"><button class="btn primary" type="submit">{{if .Expired}}Renew key{{else}}Rotate key{{end}}</button></form>
  <form method="post" action="{{.FormAction}}" onsubmit="return confirm('Revoke your personal key? Anything using it stops working.')"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="action" value="revoke"><button class="btn ghost-danger" type="submit">Revoke</button></form>
</div>
<p class="note">Rotating gives you a new secret and stops the old one.</p>{{end}}
{{else if not .Done}}
<form class="connect-form" method="post" action="{{.FormAction}}"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="action" value="create"><button class="btn primary" type="submit">Create personal key</button></form>
<p class="note">It lasts 90 days. The secret is shown once, here.</p>
{{end}}
{{if .Done}}<p class="note">You can close this page. This link will not open again.</p>{{end}}
{{if not .Unavailable}}<div class="usage"><h2>Use it</h2>
<div class="snip">
<div class="snip-head"><div class="snip-tabs" role="tablist" aria-label="Ways to use your key">{{range $i, $s := .Snippets}}<button type="button" class="snip-tab" role="tab" id="snip-tab-{{$s.ID}}" aria-controls="snip-{{$s.ID}}" aria-selected="{{if eq $i 0}}true{{else}}false{{end}}" data-snip="{{$s.ID}}">{{$s.Label}}</button>{{end}}</div>
<button class="btn secondary snip-copy" type="button" id="snip-copy">Copy</button></div>
{{range $i, $s := .Snippets}}<div class="snip-panel" role="tabpanel" id="snip-{{$s.ID}}" aria-labelledby="snip-tab-{{$s.ID}}"{{if ne $i 0}} hidden{{end}}><textarea class="snip-raw" hidden readonly>{{$s.Code}}</textarea><pre><code>{{range $s.Lines}}<span class="ln"><span class="n" aria-hidden="true">{{.N}}</span><span class="t">{{range .Tokens}}{{if .Kind}}<span class="tk-{{.Kind}}">{{.Text}}</span>{{else}}{{.Text}}{{end}}{{else}} {{end}}</span></span>{{end}}</code></pre></div>{{end}}
</div>
</div>{{end}}
<script>
(function(){
var b=document.getElementById('copy');
if(b)b.addEventListener('click',function(){navigator.clipboard.writeText(document.getElementById('secret').textContent).then(function(){b.textContent='Copied';});});
var tabs=document.querySelectorAll('.snip-tab');
tabs.forEach(function(tab){tab.addEventListener('click',function(){tabs.forEach(function(o){var on=o===tab;o.setAttribute('aria-selected',on?'true':'false');document.getElementById('snip-'+o.getAttribute('data-snip')).hidden=!on;});});});
var c=document.getElementById('snip-copy');
if(c)c.addEventListener('click',function(){var raw=document.querySelector('.snip-panel:not([hidden]) .snip-raw');if(!raw)return;
navigator.clipboard.writeText(raw.value).then(function(){c.textContent='Copied';setTimeout(function(){c.textContent='Copy';},1500);});});
})();
</script>
</div></body></html>`))

var personalKeyProblemTmpl = template.Must(template.New("personal-key-problem").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
` + pageFonts + `
<title>{{.Title}} - NeuralTrust TrustGate</title><style>` + pageCSS + `</style></head>
<body class="dotted"><div class="card">` + brandHeader + `
<h1>{{.Title}}</h1>
<p class="sub">{{.Body}}</p>
{{if .Signed}}<p class="sub">This browser is signed in as <strong>{{.Signed}}</strong>.</p>{{end}}
</div></body></html>`))

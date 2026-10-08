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
	Code  string
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
	mcp, _ := json.MarshalIndent(map[string]any{"mcpServers": map[string]any{"trustgate-store": map[string]any{
		"url": mcpURL, "headers": map[string]string{"Authorization": "Bearer " + personalKeyPlaceholder},
	}}}, "", "  ")
	out = append(out, personalKeySnippet{ID: "mcp", Label: "MCP client", Code: string(mcp)})
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
.usage details{border:1px solid var(--stroke);border-radius:var(--radius-md);margin:0 0 8px}
.usage summary{cursor:pointer;padding:10px 12px;font-size:.8125rem;font-weight:500}
.usage pre{margin:0;padding:12px;overflow-x:auto;border-top:1px solid var(--stroke);
  font-family:var(--font-mono);font-size:.75rem;line-height:1.1rem;color:var(--fg-secondary)}
.flash.ok{background:var(--badge-green-bg);color:var(--badge-green);border-color:transparent}
`

var personalKeyPageTmpl = template.Must(template.New("personal-key").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
` + pageFonts + `
<title>Personal key - NeuralTrust TrustGate</title><style>` + pageCSS + personalKeyCSS + `</style></head>
<body class="dotted"><div class="card">` + brandHeader + `
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
{{range $i, $s := .Snippets}}<details{{if eq $i 0}} open{{end}}><summary>{{$s.Label}}</summary><pre><code>{{$s.Code}}</code></pre></details>{{end}}
</div>{{end}}
<script>
(function(){var b=document.getElementById('copy');if(!b)return;b.addEventListener('click',function(){
var t=document.getElementById('secret').textContent;navigator.clipboard.writeText(t).then(function(){b.textContent='Copied';});});})();
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

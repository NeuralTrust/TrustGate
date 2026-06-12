package oauth

import (
	"bytes"
	"html/template"
	"net/url"
	"strings"

	appoauth "github.com/NeuralTrust/AgentGateway/pkg/app/oauth"
	"github.com/gofiber/fiber/v2"
)

const pageCSS = `
:root{
  --bg:#08080a;--surface:#0e0e11;--elevated:#18181d;--border:#232329;
  --border-strong:#2e2e36;--fg:#ededf0;--muted:#8a8a94;--faint:#5c5c66;
  --accent:#7c7cff;--accent-hover:#8f8fff;--success:#4ade80;--danger:#f87171;
  --danger-soft:#2a1416;--radius:9px;--radius-lg:13px;
}
*{box-sizing:border-box;border-color:var(--border)}
html{color-scheme:dark}
body{
  margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
  background:var(--bg);color:var(--fg);
  background-image:radial-gradient(circle at 1px 1px,rgba(255,255,255,.04) 1px,transparent 0);
  background-size:28px 28px;
  font-family:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;
  -webkit-font-smoothing:antialiased;
}
.card{
  width:100%;max-width:560px;margin:40px 16px;padding:32px;
  background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-lg);
  box-shadow:0 16px 48px rgba(0,0,0,.45);
}
.brand{display:flex;align-items:center;gap:10px;margin-bottom:24px}
.brand .mark{
  width:28px;height:28px;border-radius:8px;flex:none;
  background:linear-gradient(135deg,var(--accent),#4f4fd9);
  display:flex;align-items:center;justify-content:center;
  color:#fff;font-weight:700;font-size:14px;
}
.brand .name{font-weight:600;font-size:14px;letter-spacing:.01em}
.brand .product{color:var(--faint);font-size:14px}
h1{font-size:19px;font-weight:600;margin:0 0 6px}
p.sub{color:var(--muted);margin:0 0 24px;font-size:13.5px;line-height:1.55}
code{
  font-family:ui-monospace,"SF Mono",Menlo,monospace;font-size:12.5px;
  background:var(--elevated);border:1px solid var(--border);border-radius:5px;padding:1px 6px;
}
.flash{
  background:var(--danger-soft);color:var(--danger);border:1px solid #4a2226;
  border-radius:var(--radius);padding:10px 14px;font-size:13px;margin-bottom:16px;
}
.row{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:16px 0;border-top:1px solid var(--border)}
.row:last-of-type{border-bottom:1px solid var(--border)}
.name{font-weight:600;font-size:14px;text-transform:capitalize}
.reg{color:var(--faint);font-size:12px;margin-top:2px}
.status{display:inline-flex;align-items:center;gap:6px;font-size:12.5px;color:var(--success)}
.status .dot{width:7px;height:7px;border-radius:99px;background:var(--success);flex:none}
.actions{display:flex;align-items:center;gap:10px;flex:none}
a.btn,button.btn{
  display:inline-block;border-radius:var(--radius);padding:8px 18px;font-size:13.5px;font-weight:600;
  font-family:inherit;text-decoration:none;cursor:pointer;border:1px solid transparent;
  background:var(--accent);color:#fff;transition:background .12s ease;
}
a.btn:hover,button.btn:hover{background:var(--accent-hover)}
button.revoke{background:transparent;color:var(--danger);border-color:var(--border-strong)}
button.revoke:hover{background:var(--danger-soft)}
a.btn.continue{background:var(--success);color:#08240f}
a.btn.continue:hover{background:#6ee7a0}
.resume{margin-top:24px;padding-top:20px;border-top:1px solid var(--border-strong);display:flex;align-items:center;justify-content:space-between;gap:12px}
.empty{color:var(--muted);font-size:13.5px;padding:20px 0}
.center{text-align:center}
.center .brand{justify-content:center}
.center h1{margin-top:18px}
.center p.sub{margin-bottom:28px}
.center p.sub strong{color:var(--fg);font-weight:600}
.center p.sub em{font-style:normal;color:var(--fg)}
.check{
  width:48px;height:48px;border-radius:99px;margin:26px auto 0;
  display:flex;align-items:center;justify-content:center;
  color:var(--success);background:rgba(74,222,128,.1);border:1px solid rgba(74,222,128,.25);
}
.hint{color:var(--faint);font-size:12.5px;margin-top:18px;line-height:1.5}
.hint a{color:var(--muted);text-decoration:underline;text-underline-offset:2px}
.hint a:hover{color:var(--fg)}
`

const brandHeader = `<div class="brand"><div class="mark">N</div><div class="name">NeuralTrust</div><div class="product">/ TrustGate</div></div>`

var connectPageTmpl = template.Must(template.New("connect").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Connect accounts - NeuralTrust TrustGate</title><style>` + pageCSS + `</style></head>
<body><div class="card">` + brandHeader + `
<h1>Connect your accounts</h1>
<p class="sub">Virtual MCP <code>{{.ConsumerPath}}</code> needs access to these services on your behalf. Tokens are stored encrypted in the gateway vault and are never exposed to the agent.</p>
{{if .Flash}}<div class="flash">{{.Flash}}</div>{{end}}
{{if not .Providers}}<p class="empty">No third-party providers are configured for this virtual MCP.</p>{{end}}
{{range .Providers}}<div class="row">
  <div><div class="name">{{.Provider}}</div><div class="reg">{{.Registry}}</div></div>
  <div class="actions">{{if .Linked}}
    <span class="status"><span class="dot"></span>Connected</span>
    <form method="post" action="/oauth/disconnect/{{.Provider}}?ticket={{$.Ticket}}"><button class="btn revoke">Revoke</button></form>
  {{else}}
    <a class="btn" href="/oauth/connect/{{.Provider}}?ticket={{$.Ticket}}">Connect</a>
  {{end}}</div>
</div>{{end}}
{{if .ResumeURL}}<div class="resume">
  <div><div class="name">Done connecting?</div><div class="reg">Return to your application to finish signing in.</div></div>
  <a class="btn continue" href="{{.ResumeURL}}">Continue</a>
</div>{{end}}
</div></body></html>`))

var deepLinkPageTmpl = template.Must(template.New("deeplink").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Authentication complete - NeuralTrust TrustGate</title><style>` + pageCSS + `
.card{display:none}
.card.show{display:block;animation:fade-in .25s ease}
@keyframes fade-in{from{opacity:0}to{opacity:1}}
</style></head>
<body><div class="card center" id="fallback">` + brandHeader + `
<div class="check"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg></div>
<h1>Authentication complete</h1>
<p class="sub">Still here? Choose <em>Open {{.AppName}}</em> in your browser&rsquo;s dialog, or use the button below, then close this tab.</p>
<a class="btn" id="open" href="{{.Location}}">Open {{.AppName}}</a>
<p class="hint">Nothing happens? <a href="#" id="copy">Copy the link</a> and open it manually.</p>
<script>
  var target = {{.Location}};
  window.location.href = target;
  setTimeout(function () {
    document.getElementById('fallback').classList.add('show');
  }, 2500);
  document.getElementById('copy').addEventListener('click', function (e) {
    e.preventDefault();
    if (!navigator.clipboard) return;
    var el = e.target;
    navigator.clipboard.writeText(target).then(function () { el.textContent = 'copied!'; });
  });
</script>
</div></body></html>`))

type connectPageView struct {
	ConsumerPath string
	Flash        string
	Ticket       string
	Providers    []appoauth.ProviderStatus
	ResumeURL    template.URL
}

func renderConnectPage(c *fiber.Ctx, page *appoauth.ConnectPage, ticket, flash string) error {
	return renderHTML(c, connectPageTmpl, connectPageView{
		ConsumerPath: page.ConsumerPath,
		Flash:        flash,
		Ticket:       ticket,
		Providers:    page.Providers,
		ResumeURL:    template.URL(page.ResumeURL), // #nosec G203 -- gateway-built from the registered redirect_uri, never user input
	})
}

var knownSchemeApps = map[string]string{
	"cursor":          "Cursor",
	"vscode":          "VS Code",
	"vscode-insiders": "VS Code Insiders",
	"windsurf":        "Windsurf",
	"zed":             "Zed",
	"claude":          "Claude",
	"jetbrains":       "your JetBrains IDE",
	"chatgpt":         "ChatGPT",
	"cline":           "Cline",
}

func appNameForLocation(location string) string {
	u, err := url.Parse(location)
	if err != nil {
		return "your application"
	}
	if name, ok := knownSchemeApps[strings.ToLower(u.Scheme)]; ok {
		return name
	}
	return "your application"
}

type deepLinkView struct {
	AppName  string
	Location template.URL
}

func renderDeepLinkPage(c *fiber.Ctx, location string) error {
	return renderHTML(c, deepLinkPageTmpl, deepLinkView{
		AppName:  appNameForLocation(location),
		Location: template.URL(location), // #nosec G203 -- redirect target validated against the client's registered redirect_uris
	})
}

func renderHTML(c *fiber.Ctx, tmpl *template.Template, data any) error {
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return err
	}
	c.Set(fiber.HeaderContentType, fiber.MIMETextHTMLCharsetUTF8)
	return c.Status(fiber.StatusOK).Send(buf.Bytes())
}

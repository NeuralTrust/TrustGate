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

import "html/template"

const pageFonts = `<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link href="https://fonts.googleapis.com/css2?family=Inter:ital,opsz,wght@0,14..32,400;0,14..32,500;0,14..32,600&amp;family=JetBrains+Mono:wght@400;500&amp;display=swap" rel="stylesheet">`

const pageCSS = `
:root{
  --bg-canvas:#03020f;--bg-default:#03020f;--bg-muted:#1a1a28;--bg-surface-hover:#11101d;
  --fg-default:#fcfcfc;--fg-secondary:#c4c2ca;--fg-muted:#999;--fg-disabled:#888;
  --fg-on-brand:#fff;--fg-danger:#ff5b67;--fg-brand:#9053ff;
  --stroke:#272730;--brand:#9053ff;--brand-hover:#a370ff;--brand-active:#653ab3;--brand-focus:#bf9bff;
  --badge-green:#00fe18;--badge-red:#ff3948;--danger-solid:#ff3948;--danger-hover:#ff5b67;
  --danger-active:#b32832;--danger-subtle:#350d1a;
  --radius-sm:6px;--radius-md:8px;--radius-lg:12px;--radius-xl:16px;--radius-full:9999px;
  --bg-inverse:#fcfcfc;--fg-success:#30a46c;
  --font-sans:Inter,ui-sans-serif,system-ui,-apple-system,sans-serif;
  --font-mono:"JetBrains Mono",ui-monospace,SFMono-Regular,Menlo,monospace;
  --shadow-brand:0 1px 2px 0 rgb(14 18 27 / .24);
  --shadow-overlay:0 16px 32px -8px rgb(0 0 0 / .55);
  --duration-fast:100ms;
}
*{box-sizing:border-box}
html{color-scheme:dark}
body{
  margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
  background:var(--bg-canvas);color:var(--fg-default);font-family:var(--font-sans);
  -webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale;
}
body.store{display:block;align-items:stretch}
.shell{width:100%;max-width:1100px;margin:0 auto;padding:32px 24px 40px}
.card{
  width:100%;max-width:560px;margin:40px 16px;padding:24px;
  background:var(--bg-muted);border:1px solid var(--stroke);border-radius:var(--radius-lg);
  box-shadow:var(--shadow-overlay);
}
.brand{display:flex;align-items:center;gap:10px;margin-bottom:24px}
.brand .mark{
  width:28px;height:28px;border-radius:var(--radius-md);flex:none;overflow:hidden;
  display:flex;align-items:center;justify-content:center;
}
.brand .mark svg{width:100%;height:100%;display:block}
.brand .name{font-size:.875rem;line-height:1rem;font-weight:600;color:var(--fg-default)}
.brand .product{font-size:.875rem;line-height:1rem;color:var(--fg-disabled)}
h1{font-size:1.125rem;line-height:1.75rem;font-weight:600;margin:0 0 8px}
p.sub{color:var(--fg-muted);margin:0 0 24px;font-size:.875rem;line-height:1.25rem;font-weight:400}
code{
  font-family:var(--font-mono);font-size:.75rem;line-height:1rem;font-weight:400;
  background:var(--bg-surface-hover);border:1px solid var(--stroke);border-radius:var(--radius-sm);padding:1px 6px;
  color:var(--fg-secondary);
}
.flash{
  display:flex;align-items:center;gap:10px;margin-bottom:16px;padding:12px 16px;
  background:var(--danger-subtle);color:var(--fg-danger);border:1px solid rgb(255 91 103 / .2);
  border-radius:var(--radius-md);font-size:.875rem;line-height:1rem;
}
.flash svg{flex:none}
.toolbar{display:flex;align-items:center;gap:12px;margin:0 0 16px;flex-wrap:wrap}
.toolbar .input{flex:1;min-width:220px;max-width:360px}
.count{font-size:.75rem;line-height:1rem;color:var(--fg-muted);margin-left:auto}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px}
.tile{display:flex;flex-direction:column;min-width:0}
.tile-body{
  flex:1;display:flex;flex-direction:column;gap:12px;min-height:194px;padding:12px;
  background:var(--bg-surface-hover);border:1px solid var(--stroke);
  border-radius:var(--radius-md) var(--radius-md) 0 0;margin-bottom:-1px;
  transition:background var(--duration-fast);
}
.tile-foot{
  display:flex;align-items:center;justify-content:space-between;gap:12px;padding:12px;
  background:var(--bg-surface-hover);border:1px solid var(--stroke);
  border-radius:0 0 var(--radius-md) var(--radius-md);
  transition:background var(--duration-fast);
}
.tile:hover .tile-body,.tile:hover .tile-foot{background:var(--bg-muted)}
.logo{
  width:60px;height:60px;border-radius:var(--radius-md);flex:none;
  display:flex;align-items:center;justify-content:center;background:var(--stroke);
}
.logo img{width:40px;height:40px;object-fit:contain;display:block}
.name{font-size:.875rem;line-height:1.25rem;font-weight:500;letter-spacing:-.072px;color:var(--fg-default);margin:0}
.desc{
  margin:0;color:var(--fg-muted);font-size:.875rem;line-height:1.25rem;
  display:-webkit-box;-webkit-line-clamp:3;-webkit-box-orient:vertical;overflow:hidden;
}
.reg{color:var(--fg-muted);font-size:.875rem;line-height:1.25rem}
.badge{
  display:inline-flex;align-items:center;gap:4px;padding:4px 8px;border-radius:var(--radius-full);
  font-size:.75rem;line-height:1rem;font-weight:400;white-space:nowrap;
}
.badge svg{flex:none}
.badge.green{color:var(--badge-green);background:rgb(0 254 24 / .2)}
.badge.red{color:var(--badge-red);background:rgb(255 57 72 / .2)}
a.btn,button.btn{
  box-sizing:border-box;display:inline-flex;align-items:center;justify-content:center;gap:8px;
  height:32px;padding:0 12px;border-radius:var(--radius-md);
  font-family:inherit;font-size:.875rem;line-height:1rem;font-weight:500;
  text-decoration:none;cursor:pointer;border:1px solid transparent;
  transition:background var(--duration-fast),border-color var(--duration-fast),color var(--duration-fast),box-shadow var(--duration-fast);
}
a.btn:focus-visible,button.btn:focus-visible{outline:none}
a.btn.primary,button.btn.primary{
  background:var(--brand);color:var(--fg-on-brand);box-shadow:var(--shadow-brand);
}
a.btn.primary:hover,button.btn.primary:hover{background:var(--brand-hover)}
a.btn.primary:active,button.btn.primary:active{background:var(--brand-active);box-shadow:none}
a.btn.primary:focus-visible,button.btn.primary:focus-visible{box-shadow:inset 0 0 0 1px var(--brand-focus)}
a.btn.secondary,button.btn.secondary{
  background:var(--bg-default);color:var(--fg-default);border-color:var(--stroke);
}
a.btn.secondary:hover,button.btn.secondary:hover{background:var(--bg-surface-hover)}
a.btn.secondary:active,button.btn.secondary:active{background:var(--bg-muted)}
a.btn.secondary:focus-visible,button.btn.secondary:focus-visible{border-color:var(--brand)}
button.btn.ghost-danger{
  background:transparent;color:var(--danger-solid);text-decoration:underline;text-underline-offset:2px;
}
button.btn.ghost-danger:hover{color:var(--danger-hover)}
button.btn.ghost-danger:active{color:var(--danger-active)}
.tile-foot .btn.ghost-danger{color:var(--fg-danger);text-decoration:none}
.tile-foot .btn.ghost-danger:hover{text-decoration:underline;text-underline-offset:2px}
.resume{
  margin-top:20px;padding:12px 16px;border:1px solid var(--stroke);border-radius:var(--radius-md);
  background:var(--bg-muted);box-shadow:var(--shadow-overlay);
  display:flex;align-items:center;justify-content:space-between;gap:12px;
  position:sticky;bottom:16px;
}
.empty{color:var(--fg-muted);font-size:.875rem;line-height:1.25rem;padding:8px 0}
.center{text-align:center}
.center .brand{justify-content:center}
.center h1{margin-top:16px}
.center p.sub{margin-bottom:24px}
.center p.sub strong{color:var(--fg-default);font-weight:600}
.center p.sub em{font-style:normal;color:var(--fg-default)}
.check{
  width:48px;height:48px;border-radius:var(--radius-full);margin:24px auto 0;
  display:flex;align-items:center;justify-content:center;
  color:var(--badge-green);background:rgb(0 254 24 / .2);
}
.hint{color:var(--fg-disabled);font-size:.75rem;line-height:1rem;margin-top:16px}
.hint a{color:var(--fg-muted);text-decoration:underline;text-underline-offset:2px}
.hint a:hover{color:var(--fg-default)}
.input{
  position:relative;display:flex;align-items:center;height:46px;padding:0 16px;
  background:var(--bg-default);border:1px solid var(--stroke);border-radius:var(--radius-md);
}
.input:hover{background:var(--bg-surface-hover)}
.input:focus-within{border-color:var(--brand)}
.input input{
  width:100%;height:100%;border:0;background:transparent;color:var(--fg-default);
  font-family:inherit;font-size:.875rem;line-height:1rem;font-weight:500;padding:20px 0 6px;outline:none;
}
.input input::placeholder{color:transparent}
.input label{
  position:absolute;left:16px;top:6px;font-size:10px;line-height:14px;color:var(--fg-muted);pointer-events:none;
  transition:top var(--duration-fast),transform var(--duration-fast),font-size var(--duration-fast),line-height var(--duration-fast);
}
.input input:placeholder-shown:not(:focus){padding:0}
.input input:placeholder-shown:not(:focus)+label{
  top:50%;transform:translateY(-50%);font-size:.875rem;line-height:18px;
}
.connect-form{display:flex;flex-direction:column;gap:16px}
.connect-form .btn{align-self:flex-start}

/* ── Focused card pages: dotted canvas, full-bleed hero, footer CTA ── */
/* The canvas is a faint dot field with a brand-tinted pool of light behind the
   card, so the card reads as lit rather than pasted on flat black. */
body.dotted{
  background-color:var(--bg-canvas);
  background-image:
    radial-gradient(rgb(255 255 255 / .03) 1px,transparent 1px),
    radial-gradient(46% 42% at 50% 44%,rgb(144 83 255 / .05) 0%,transparent 72%);
  background-size:24px 24px,100% 100%;
  background-position:-12px -12px,0 0;
  background-attachment:fixed,fixed;
}
.card.flush{
  max-width:428px;padding:0;overflow:hidden;border-radius:var(--radius-xl);
  background:var(--bg-muted);border-color:var(--stroke);
  box-shadow:
    inset 0 1px 0 rgb(255 255 255 / .06),
    0 1px 2px rgb(0 0 0 / .5),
    0 28px 56px -20px rgb(0 0 0 / .72);
}
.card-hero{
  position:relative;display:flex;align-items:center;justify-content:center;height:104px;
  background:
    radial-gradient(52% 84% at 50% 48%,rgb(144 83 255 / .20) 0%,rgb(144 83 255 / .05) 54%,transparent 78%),
    var(--bg-muted);
}
.card-hero::after,.card-foot::before{
  content:"";position:absolute;left:0;right:0;height:1px;
  background:linear-gradient(90deg,transparent,var(--stroke) 14%,var(--stroke) 86%,transparent);
}
.card-hero::after{bottom:0}
.card-foot::before{top:0}
/* gap:0 plus an explicit connector element keeps the line inside the pair —
   a wider absolutely-positioned rule would overhang both marks. */
.pair{position:relative;display:flex;align-items:center;gap:0}
.pair .link{
  width:24px;height:1px;flex:none;
  background:linear-gradient(90deg,rgb(191 155 255 / .3),var(--brand-focus),rgb(191 155 255 / .3));
  box-shadow:0 0 5px rgb(144 83 255 / .45);
}
.mark-tile{
  position:relative;width:52px;height:52px;flex:none;overflow:hidden;
  display:flex;align-items:center;justify-content:center;
  border-radius:16px;background:var(--bg-inverse);
  box-shadow:
    inset 0 0 0 1px rgb(0 0 0 / .06),
    0 2px 4px rgb(0 0 0 / .28),
    0 14px 26px -10px rgb(0 0 0 / .7);
}
.mark-tile img{width:30px;height:30px;object-fit:contain;display:block}
.mark-tile.nt{
  background:var(--bg-canvas);
  box-shadow:
    inset 0 0 0 1px rgb(255 255 255 / .08),
    0 2px 4px rgb(0 0 0 / .28),
    0 14px 26px -10px rgb(0 0 0 / .7);
}
.mark-tile.nt svg{width:100%;height:100%;display:block}
.card-body{padding:24px 28px 22px}
h1.title{
  font-size:1.125rem;line-height:1.75rem;font-weight:600;letter-spacing:-.014em;
  margin:0 0 4px;text-wrap:balance;
}
p.lede{
  margin:0;color:var(--fg-muted);
  font-size:.8125rem;line-height:1.25rem;letter-spacing:-.002em;text-wrap:pretty;
}
.card-body .flash{margin:18px 0 0}
/* What the connection grants — the substance of a consent screen. */
.access{margin-top:20px}
.eyebrow{
  display:block;margin:0 0 9px;color:var(--fg-disabled);
  font-size:.6875rem;line-height:1rem;font-weight:500;letter-spacing:.07em;text-transform:uppercase;
}
.chips{display:flex;flex-wrap:wrap;gap:6px}
.chip{
  font-family:var(--font-mono);font-size:.6875rem;line-height:1rem;font-weight:400;
  padding:4px 7px;border-radius:var(--radius-sm);
  background:var(--bg-surface-hover);border:1px solid var(--stroke);color:var(--fg-secondary);
}
.chip.more{
  font-family:var(--font-sans);background:transparent;border-color:transparent;
  color:var(--fg-disabled);padding:4px 2px;
}
.note{
  display:flex;gap:8px;margin:16px 0 0;
  color:var(--fg-disabled);font-size:.75rem;line-height:1.125rem;
}
.note svg{flex:none;margin-top:1px}
.account{
  display:inline-flex;align-items:center;gap:7px;margin-top:18px;padding:5px 11px;
  background:var(--bg-surface-hover);border:1px solid var(--stroke);border-radius:var(--radius-full);
  color:var(--fg-secondary);font-size:.8125rem;line-height:1.125rem;
}
.account svg{flex:none;color:var(--fg-success)}
.account.danger svg{color:var(--fg-danger)}
.card-foot{
  position:relative;display:flex;flex-direction:column;gap:6px;align-items:stretch;
  padding:18px 28px 20px;background:var(--bg-muted);
}
.card-foot form{display:flex;width:100%}
a.btn.block,button.btn.block{
  width:100%;height:44px;border-radius:10px;font-weight:500;letter-spacing:-.006em;
}
/* A hairline top light and a brand-tinted lift keep the full-width CTA from
   reading as a flat slab; the fill itself stays the brand token. */
a.btn.primary.block,button.btn.primary.block{
  box-shadow:
    inset 0 1px 0 rgb(255 255 255 / .14),
    0 1px 2px rgb(0 0 0 / .35);
}
a.btn.primary.block:hover,button.btn.primary.block:hover{
  box-shadow:
    inset 0 1px 0 rgb(255 255 255 / .18),
    0 1px 2px rgb(0 0 0 / .35);
}
a.btn.primary.block:active,button.btn.primary.block:active{
  box-shadow:inset 0 1px 2px rgb(0 0 0 / .25);
}
a.btn.ghost,button.btn.ghost{
  background:transparent;color:var(--fg-muted);font-weight:400;
  text-decoration:underline;text-underline-offset:2px;
}
a.btn.ghost:hover,button.btn.ghost:hover{color:var(--fg-default)}
.card-foot .btn.ghost,.card-foot .btn.ghost-danger{
  height:26px;font-weight:400;font-size:.8125rem;text-decoration:none;
}
.card-foot .btn.ghost:hover,.card-foot .btn.ghost-danger:hover{
  text-decoration:underline;text-underline-offset:2px;
}
.card-foot .btn.ghost-danger{color:var(--fg-danger)}
.secured{
  display:flex;align-items:center;justify-content:center;gap:7px;
  margin-top:4px;color:var(--fg-disabled);
  font-size:.75rem;line-height:1rem;letter-spacing:.004em;
}
/* The mark goes monochrome here: the gradient tile turns to mud below ~20px. */
.secured svg{display:block;flex:none;opacity:.85}
`

const brandMark = `<svg viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><g clip-path="url(#ntClip)"><path fill="url(#ntGrad)" d="M32 0H0v32h32z"/><path fill="#fff" d="M18.092 20.06a.67.67 0 0 1-.55.3.7.7 0 0 1-.565-.286l-2.704-3.814-1.45 2.103 2.197 3.098a3.08 3.08 0 0 0 2.51 1.297h.038a3.06 3.06 0 0 0 2.502-1.342l8.02-11.477h-2.926z"/><path fill="#fff" d="M14.292 11.518a.63.63 0 0 1 .552.286l2.652 3.74 1.449-2.103-2.145-3.024a3.08 3.08 0 0 0-2.509-1.297h-.039a3.06 3.06 0 0 0-2.506 1.35L3.925 21.85l-.085.123h2.91l6.98-10.155a.68.68 0 0 1 .562-.3"/></g><defs><linearGradient id="ntGrad" x1="30.667" x2="6.667" y1="0" y2="32" gradientUnits="userSpaceOnUse"><stop stop-color="#03AFFF"/><stop offset="1" stop-color="#9B29FF"/></linearGradient><clipPath id="ntClip"><path fill="#fff" d="M0 0h32v32H0z"/></clipPath></defs></svg>`

const brandGlyph = `<svg width="17" height="10" viewBox="3 8 27 16" fill="currentColor" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path d="M18.092 20.06a.67.67 0 0 1-.55.3.7.7 0 0 1-.565-.286l-2.704-3.814-1.45 2.103 2.197 3.098a3.08 3.08 0 0 0 2.51 1.297h.038a3.06 3.06 0 0 0 2.502-1.342l8.02-11.477h-2.926z"/><path d="M14.292 11.518a.63.63 0 0 1 .552.286l2.652 3.74 1.449-2.103-2.145-3.024a3.08 3.08 0 0 0-2.509-1.297h-.039a3.06 3.06 0 0 0-2.506 1.35L3.925 21.85l-.085.123h2.91l6.98-10.155a.68.68 0 0 1 .562-.3"/></svg>`

const brandHeader = `<div class="brand"><div class="mark">` + brandMark + `</div><div class="name">NeuralTrust</div><div class="product">/ TrustGate</div></div>`

const securedByFooter = `<div class="secured">` + brandGlyph + `Secured by NeuralTrust TrustGate</div>`

const lockGlyph = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect width="18" height="11" x="3" y="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>`

const alertGlyph = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg>`

const badgeCheck = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/></svg>`

var connectPageTmpl = template.Must(template.New("connect").Parse(`<!doctype html>
<html lang="en" class="dark"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
` + pageFonts + `
<title>Connect accounts - NeuralTrust TrustGate</title><style>` + pageCSS + `</style></head>
<body class="store dotted"><div class="shell">` + brandHeader + `
<h1>Connect your accounts</h1>
<p class="sub">Choose which MCP servers virtual MCP <code>{{.ConsumerPath}}</code> may use. Connect only the ones you need — tokens are stored encrypted in the gateway vault and are never exposed to the agent.</p>
{{if .Flash}}<div class="flash" role="status"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"/><path d="m15 9-6 6"/><path d="m9 9 6 6"/></svg><div>{{.Flash}}</div></div>{{end}}
{{if .Providers}}<div class="toolbar">
  <div class="input">
    <input id="filter" type="search" placeholder=" " autocomplete="off">
    <label for="filter">Search MCP servers</label>
  </div>
  <div class="count"><span id="shown">{{len .Providers}}</span> of {{len .Providers}}</div>
</div>{{end}}
{{if not .Providers}}<p class="empty">No third-party providers are configured for this virtual MCP.</p>{{end}}
<p class="empty" id="no-match" hidden>No matching MCP servers.</p>
<div class="grid">{{range .Providers}}<article class="tile" data-filter="{{.DisplayName}} {{.Subtitle}} {{.Provider}}">
  <div class="tile-body">
    <div class="logo"><img src="{{.LogoURL}}" alt="" width="40" height="40" onerror="this.onerror=null;this.src='/oauth/brands/mcp.svg'"></div>
    <div>
      <p class="name">{{.DisplayName}}</p>
      <p class="desc">{{.Description}}</p>
    </div>
  </div>
  <div class="tile-foot">{{if .NeedsReconnect}}
    <span class="badge red">Expired</span>
    <form method="post" action="/oauth/connect/{{.Provider}}?ticket={{$.Ticket}}"><button class="btn secondary" type="submit">Reconnect</button></form>
  {{else if .Linked}}
    <div>{{if .AccountRef}}<span class="reg">{{.AccountRef}}</span>{{end}}
    <span class="badge green">` + badgeCheck + `Connected</span></div>
    <form method="post" action="/oauth/disconnect/{{.Provider}}?ticket={{$.Ticket}}"><button class="btn ghost-danger" type="submit">Revoke</button></form>
  {{else}}
    <span></span>
    <form method="post" action="/oauth/connect/{{.Provider}}?ticket={{$.Ticket}}"><button class="btn secondary" type="submit">Connect</button></form>
  {{end}}</div>
</article>{{end}}</div>
{{if .ResumeURL}}<div class="resume">
  <div><div class="name">Done connecting?</div><div class="reg">Return to your application to finish signing in.</div></div>
  <a class="btn primary" href="{{.ResumeURL}}">Continue</a>
</div>{{end}}
<script>
(function () {
  var input = document.getElementById('filter');
  if (!input) return;
  var tiles = document.querySelectorAll('.tile');
  var shown = document.getElementById('shown');
  var empty = document.getElementById('no-match');
  input.addEventListener('input', function () {
    var q = input.value.toLowerCase().trim();
    var n = 0;
    tiles.forEach(function (tile) {
      var hit = !q || (tile.getAttribute('data-filter') || '').toLowerCase().indexOf(q) !== -1;
      tile.hidden = !hit;
      if (hit) n++;
    });
    if (shown) shown.textContent = String(n);
    if (empty) empty.hidden = n !== 0;
  });
})();
</script>
</div></body></html>`))

var configurePageTmpl = template.Must(template.New("configure").Parse(`<!doctype html>
<html lang="en" class="dark"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
` + pageFonts + `
<title>Configure {{.ServerName}} - NeuralTrust TrustGate</title><style>` + pageCSS + `</style></head>
<body class="dotted"><div class="card">` + brandHeader + `
<h1>Configure {{.ServerName}}</h1>
<p class="sub">Enter your setup values for {{.ServerName}}. These are stored for your account only — secret values are kept encrypted in the gateway vault and are never exposed to the agent.</p>
{{if .Saved}}<div class="flash" role="status"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/></svg><div>Saved. You can return to your application.</div></div>{{end}}
<form class="connect-form" method="post">
  {{range .Variables}}<div class="input">
    <input id="{{.Name}}" name="{{.Name}}" type="{{if .Secret}}password{{else}}text{{end}}" autocomplete="off"{{if and .Required (not .Set)}} required{{end}} placeholder=" ">
    <label for="{{.Name}}">{{.Name}}{{if .Set}} (set — leave blank to keep){{else if not .Required}} (optional){{end}}</label>
  </div>{{end}}
  <button class="btn primary" type="submit">Save</button>
</form>
</div></body></html>`))

var singleConnectPageTmpl = template.Must(template.New("single-connect").Parse(`<!doctype html>
<html lang="en" class="dark"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
` + pageFonts + `
<title>Connect {{.ServerName}} - NeuralTrust TrustGate</title><style>` + pageCSS + `</style></head>
<body class="dotted"><div class="card flush">
<div class="card-hero">
  <div class="pair">
    <div class="mark-tile nt">` + brandMark + `</div>
    <span class="link" aria-hidden="true"></span>
    <div class="mark-tile"><img src="{{.LogoURL}}" alt="" width="32" height="32" onerror="this.onerror=null;this.src='/oauth/brands/mcp.svg'"></div>
  </div>
</div>
<div class="card-body">
{{if not .Found}}
  <h1 class="title">Connect your {{.ServerName}} account</h1>
  <p class="lede">This server does not need an account connection, or it is not available on this virtual MCP.</p>
{{else}}
  {{if .Linked}}<h1 class="title">{{.ServerName}} is connected</h1>
  {{else if .NeedsReconnect}}<h1 class="title">Reconnect your {{.ServerName}} account</h1>
  {{else}}<h1 class="title">Connect your {{.ServerName}} account</h1>{{end}}
  {{if .Description}}<p class="lede">{{.Description}}</p>
  {{else if .NeedsReconnect}}<p class="lede">{{.ServerName}} expired or revoked the stored credentials.</p>
  {{else}}<p class="lede">TrustGate connects to {{.ServerName}} on your behalf.</p>{{end}}
  {{if .Flash}}<div class="flash" role="status"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"/><path d="m15 9-6 6"/><path d="m9 9 6 6"/></svg><div>{{.Flash}}</div></div>{{end}}
  {{if .AccessLabel}}<div class="access">
    <span class="eyebrow">{{.AccessLabel}}</span>
    <div class="chips">{{range .Items}}<span class="chip">{{.}}</span>{{end}}{{if .ItemsMore}}<span class="chip more">+{{.ItemsMore}} more</span>{{end}}</div>
  </div>{{end}}
  {{if .NeedsReconnect}}<div class="account danger">` + alertGlyph + `Access expired</div>
  {{else if .Linked}}<div class="account">` + badgeCheck + `{{if .AccountRef}}{{.AccountRef}}{{else}}Connected{{end}}</div>{{end}}
  <p class="note">` + lockGlyph + `<span>Credentials are encrypted in the gateway vault. The agent never sees the token.</span></p>
{{end}}
</div>
<div class="card-foot">
{{if .Found}}
  {{if .NeedsReconnect}}
    <form method="post" action="/oauth/connect/{{.Provider}}?ticket={{.Ticket}}"><button class="btn primary block" type="submit">Reconnect {{.ServerName}}</button></form>
    {{if .ResumeURL}}<a class="btn ghost block" href="{{.ResumeURL}}">Return to your app</a>{{end}}
  {{else if .Linked}}
    {{if .ResumeURL}}<a class="btn primary block" href="{{.ResumeURL}}">Return to your app</a>{{end}}
    <form method="post" action="/oauth/disconnect/{{.Provider}}?ticket={{.Ticket}}"><button class="btn ghost-danger block" type="submit">Disconnect {{.ServerName}}</button></form>
  {{else}}
    <form method="post" action="/oauth/connect/{{.Provider}}?ticket={{.Ticket}}"><button class="btn primary block" type="submit">Connect account</button></form>
    {{if .ResumeURL}}<a class="btn ghost block" href="{{.ResumeURL}}">Return to your app</a>{{end}}
  {{end}}
{{else if .ResumeURL}}
  <a class="btn secondary block" href="{{.ResumeURL}}">Return to your app</a>
{{end}}
` + securedByFooter + `
</div>
</div></body></html>`))

var apiKeyConnectPageTmpl = template.Must(template.New("api-key-connect").Parse(`<!doctype html>
<html lang="en" class="dark"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
` + pageFonts + `
<title>Connect API key - NeuralTrust TrustGate</title><style>` + pageCSS + `</style></head>
<body class="dotted"><div class="card">` + brandHeader + `
<h1>Connect with an API key</h1>
<p class="sub">Enter the API key for this virtual MCP. The key is used only to authorize this connection.</p>
<form class="connect-form" method="post" action="{{.FormAction}}">
  <div class="input">
    <input id="api-key" name="api_key" type="password" autocomplete="off" required placeholder=" ">
    <label for="api-key">API key</label>
  </div>
  <button class="btn primary" type="submit">Continue</button>
</form>
</div></body></html>`))

var deepLinkPageTmpl = template.Must(template.New("deeplink").Parse(`<!doctype html>
<html lang="en" class="dark"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
` + pageFonts + `
<title>Authentication complete - NeuralTrust TrustGate</title><style>` + pageCSS + `
.card{display:none}
.card.show{display:block;animation:fade-in .25s ease}
@keyframes fade-in{from{opacity:0}to{opacity:1}}
</style></head>
<body class="dotted"><div class="card center" id="fallback">` + brandHeader + `
<div class="check"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg></div>
<h1>Authentication complete</h1>
<p class="sub">Still here? Choose <em>Open {{.AppName}}</em> in your browser&rsquo;s dialog, or use the button below, then close this tab.</p>
<a class="btn primary" id="open" href="{{.Location}}">Open {{.AppName}}</a>
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

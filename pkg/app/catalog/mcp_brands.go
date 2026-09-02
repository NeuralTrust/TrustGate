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

package catalog

import (
	"io/fs"
	"mime"
	"path"
	"strings"
	"unicode"

	mcpcatalog "github.com/NeuralTrust/TrustGate/seed/mcp-catalog"
)

const (
	brandAssetPrefix = "/oauth/brands/"
	fallbackBrand    = "mcp.svg"
)

// vendorBrandIcons maps a normalized catalog vendor (or provider name) to a
// file under seed/mcp-catalog/brands. Keys match NeuralTrust/app mcpBrands.ts.
var vendorBrandIcons = map[string]string{
	"aha":                           "mcp/aha.png",
	"ahrefs":                        "mcp/ahrefs.png",
	"airbyte":                       "mcp/airbyte.svg",
	"airtable":                      "mcp/airtable.svg",
	"algolia":                       "mcp/algolia.svg",
	"amplitude":                     "mcp/amplitude.png",
	"apify":                         "mcp/apify.png",
	"apollo":                        "mcp/apollo.ico",
	"arcade":                        "mcp/arcade.png",
	"asana":                         "mcp/asana.svg",
	"assemblyai":                    "mcp/assemblyai.ico",
	"atlan":                         "mcp/atlan.png",
	"atlassian":                     "mcp/atlassian.svg",
	"attio":                         "mcp/attio.ico",
	"aws":                           "mcp/aws.svg",
	"axiom":                         "mcp/axiom.ico",
	"azuredevops":                   "azure_devops.svg",
	"betterstack":                   "mcp/betterstack.svg",
	"box":                           "mcp/box.svg",
	"braintrust":                    "mcp/braintrust.svg",
	"brex":                          "mcp/brex.svg",
	"brightdata":                    "mcp/brightdata.png",
	"browserbase":                   "mcp/browserbase.ico",
	"builderio":                     "mcp/builderio.ico",
	"buildkite":                     "mcp/buildkite.svg",
	"calcom":                        "mcp/caldotcom.svg",
	"calendly":                      "mcp/calendly.svg",
	"canva":                         "mcp/canva.ico",
	"chargebee":                     "mcp/chargebee.png",
	"checkr":                        "mcp/checkr.png",
	"clickhouse":                    "mcp/clickhouse.svg",
	"clickup":                       "mcp/clickup.svg",
	"close":                         "mcp/close.png",
	"cloudflareaigateway":           "mcp/cloudflare.svg",
	"cloudflareapi":                 "mcp/cloudflare.svg",
	"cloudflaredocs":                "mcp/cloudflare.svg",
	"cloudflareobservability":       "mcp/cloudflare.svg",
	"cloudflareradar":               "mcp/cloudflare.svg",
	"cloudflareworkersbindings":     "mcp/cloudflare.svg",
	"cloudinary":                    "mcp/cloudinary.svg",
	"coda":                          "mcp/coda.svg",
	"coinbase":                      "mcp/coinbase.svg",
	"composio":                      "mcp/composio.jpg",
	"contentful":                    "mcp/contentful.svg",
	"cube":                          "mcp/cube.ico",
	"customerio":                    "mcp/customerio.png",
	"daloopa":                       "mcp/daloopa.png",
	"databricks":                    "mcp/databricks.svg",
	"datadog":                       "mcp/datadog.svg",
	"dbtlabs":                       "mcp/dbtlabs.ico",
	"deepwiki":                      "mcp/deepwiki.png",
	"devexpress":                    "mcp/devexpress.svg",
	"digitaloceanaccounts":          "mcp/digitalocean.svg",
	"digitaloceanappplatform":       "mcp/digitalocean.svg",
	"digitaloceandatabases":         "mcp/digitalocean.svg",
	"digitaloceandroplets":          "mcp/digitalocean.svg",
	"digitaloceankubernetes":        "mcp/digitalocean.svg",
	"docusign":                      "mcp/docusign.png",
	"dropbox":                       "mcp/dropbox.svg",
	"dynatrace":                     "mcp/dynatrace.svg",
	"egnyte":                        "mcp/egnyte.svg",
	"elastic":                       "mcp/elastic.svg",
	"endorlabs":                     "mcp/endorlabs.png",
	"exa":                           "mcp/exa.png",
	"excalidraw":                    "mcp/excalidraw.svg",
	"fathom":                        "mcp/fathom.png",
	"fibery":                        "mcp/fibery.png",
	"figma":                         "mcp/figma.svg",
	"firecrawl":                     "mcp/firecrawl.png",
	"fireflies":                     "mcp/fireflies.ico",
	"freshworks":                    "mcp/freshworks.png",
	"front":                         "mcp/front.png",
	"github":                        "github.svg",
	"gitlab":                        "mcp/gitlab.svg",
	"glean":                         "mcp/glean.png",
	"globalping":                    "mcp/globalping.png",
	"gmail":                         "mcp/gmail.svg",
	"gooddata":                      "mcp/gooddata.ico",
	"googlecalendar":                "mcp/googlecalendar.svg",
	"googledrive":                   "mcp/googledrive.svg",
	"googlecloudandroidmanagement":  "google_cloud.svg",
	"googlecloudbigtable":           "google_cloud.svg",
	"googlecloudcomposer":           "google_cloud.svg",
	"googlecloudcomputeengine":      "google_cloud.svg",
	"googleclouddatastream":         "google_cloud.svg",
	"googleclouddeveloperknowledge": "google_cloud.svg",
	"googlecloudfirestore":          "google_cloud.svg",
	"googlecloudgke":                "google_cloud.svg",
	"googlecloudmapstools":          "google_cloud.svg",
	"googlecloudmemorystore":        "google_cloud.svg",
	"googlecloudmonitoring":         "google_cloud.svg",
	"googlecloudrun":                "google_cloud.svg",
	"googlecloudsql":                "google_cloud.svg",
	"googlecloudstitch":             "google_cloud.svg",
	"googlecloudstitchdesign":       "google_cloud.svg",
	"gorgias":                       "mcp/gorgias.png",
	"grafana":                       "mcp/grafana.svg",
	"granola":                       "mcp/granola.png",
	"guru":                          "mcp/guru.png",
	"halo":                          "mcp/halo.png",
	"hex":                           "mcp/hex.png",
	"holded":                        "mcp/holded.png",
	"honeycomb":                     "mcp/honeycomb.png",
	"hubspot":                       "mcp/hubspot.svg",
	"huggingface":                   "mcp/huggingface.svg",
	"incidentio":                    "mcp/incidentio.png",
	"infobip":                       "mcp/infobip.png",
	"intercom":                      "mcp/intercom.svg",
	"invideo":                       "mcp/invideo.ico",
	"jam":                           "mcp/jam.ico",
	"jfrog":                         "mcp/jfrog.svg",
	"jinaai":                        "mcp/jinaai.png",
	"jotform":                       "mcp/jotform.svg",
	"jumpcloud":                     "mcp/jumpcloud.png",
	"klaviyo":                       "mcp/klaviyo.png",
	"langfuse":                      "mcp/langfuse.png",
	"launchdarkly":                  "mcp/launchdarkly.ico",
	"linear":                        "mcp/linear.svg",
	"lithic":                        "mcp/lithic.png",
	"mailchimp":                     "mcp/mailchimp.svg",
	"make":                          "mcp/make.svg",
	"mem0":                          "mcp/mem0.png",
	"mercury":                       "mcp/mercury.ico",
	"microsoft":                     "mcp/microsoft.ico",
	"microsoftsentinel":             "mcp/microsoftsentinel.ico",
	"miro":                          "mcp/miro.svg",
	"mixpanel":                      "mcp/mixpanel.svg",
	"moderntreasury":                "mcp/moderntreasury.png",
	"mollie":                        "mcp/mollie.png",
	"mondaycom":                     "mcp/mondaycom.png",
	"montecarlo":                    "mcp/montecarlo.png",
	"motherduck":                    "mcp/motherduck.ico",
	"mux":                           "mcp/mux.ico",
	"n8n":                           "mcp/n8n.svg",
	"neon":                          "mcp/neon.svg",
	"netsuite":                      "mcp/netsuite.ico",
	"newrelic":                      "mcp/newrelic.svg",
	"normanfinance":                 "mcp/normanfinance.png",
	"notion":                        "mcp/notion.svg",
	"paddle":                        "mcp/paddle.svg",
	"pagerduty":                     "mcp/pagerduty.svg",
	"pandadoc":                      "mcp/pandadoc.png",
	"paypal":                        "mcp/paypal.svg",
	"pendo":                         "mcp/pendo.jpg",
	"pinecone":                      "mcp/pinecone.ico",
	"pipedream":                     "mcp/pipedream.png",
	"plaid":                         "mcp/plaid.png",
	"planetscale":                   "mcp/planetscale.svg",
	"port":                          "mcp/port.png",
	"posthog":                       "mcp/posthog.svg",
	"postman":                       "mcp/postman.svg",
	"prisma":                        "mcp/prisma.svg",
	"prismic":                       "mcp/prismic.svg",
	"railway":                       "mcp/railway.svg",
	"ramp":                          "mcp/ramp.ico",
	"razorpay":                      "mcp/razorpay.svg",
	"render":                        "mcp/render.svg",
	"replicate":                     "mcp/replicate.svg",
	"rootly":                        "mcp/rootly.ico",
	"salesforce":                    "mcp/salesforce.ico",
	"sanity":                        "mcp/sanity.svg",
	"scrapingant":                   "mcp/scrapingant.ico",
	"sectigo":                       "mcp/sectigo.svg",
	"semgrep":                       "mcp/semgrep.png",
	"semrush":                       "mcp/semrush.svg",
	"sentry":                        "mcp/sentry.svg",
	"serpapi":                       "mcp/serpapi.png",
	"servicenow":                    "mcp/servicenow.ico",
	"shopify":                       "mcp/shopify.svg",
	"shortcut":                      "mcp/shortcut.svg",
	"slack":                         "mcp/slack.svg",
	"smartbear":                     "mcp/smartbear.png",
	"smartsheet":                    "mcp/smartsheet.png",
	"snowflake":                     "mcp/snowflake.svg",
	"socket":                        "mcp/socket.svg",
	"sonarqube":                     "mcp/sonarqube.ico",
	"sonatype":                      "mcp/sonatype.svg",
	"square":                        "mcp/square.svg",
	"statsig":                       "mcp/statsig.png",
	"storyblok":                     "mcp/storyblok.png",
	"stripe":                        "mcp/stripe.svg",
	"stytch":                        "mcp/stytch.ico",
	"supabase":                      "mcp/supabase.svg",
	"tavily":                        "mcp/tavily.ico",
	"teamwork":                      "mcp/teamwork.png",
	"telnyx":                        "mcp/telnyx.ico",
	"thoughtspot":                   "mcp/thoughtspot.png",
	"tinybird":                      "mcp/tinybird.ico",
	"todoist":                       "mcp/todoist.svg",
	"twilio":                        "mcp/twilio.png",
	"vanta":                         "mcp/vanta.png",
	"vercel":                        "mcp/vercel.svg",
	"vimeo":                         "mcp/vimeo.svg",
	"vonage":                        "mcp/vonage.svg",
	"webflow":                       "mcp/webflow.svg",
	"weightsbiases":                 "mcp/weightsandbiases.svg",
	"wix":                           "mcp/wix.svg",
	"workato":                       "mcp/workato.ico",
	"zapier":                        "mcp/zapier.svg",
	"zoomdocs":                      "mcp/zoom.svg",
	"zoomrevenueaccelerator":        "mcp/zoom.svg",
	"zoomteamchat":                  "mcp/zoom.svg",
	"zoomwhiteboard":                "mcp/zoom.svg",
	"zoomworkspace":                 "mcp/zoom.svg",
}

func normalizeVendor(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(unicode.ToLower(r))
		}
	}
	return b.String()
}

func iconFile(candidates ...string) string {
	for _, raw := range candidates {
		for _, key := range vendorKeys(raw) {
			if file, ok := vendorBrandIcons[key]; ok {
				return file
			}
		}
	}
	return fallbackBrand
}

func vendorKeys(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	keys := []string{normalizeVendor(raw)}
	host := raw
	if i := strings.IndexByte(raw, '/'); i >= 0 {
		host = raw[:i]
	}
	if i := strings.LastIndexByte(host, '.'); i >= 0 && i+1 < len(host) {
		keys = append(keys, normalizeVendor(host[i+1:]))
	}
	return keys
}

// BrandIconURL returns the public path of the bundled MCP vendor logo for the
// given catalog vendor / provider identifiers. Unknown names use the generic
// MCP mark.
func BrandIconURL(candidates ...string) string {
	return brandAssetPrefix + iconFile(candidates...)
}

// ReadBrandIcon returns the embedded logo bytes and a MIME type. name is the
// path under seed/mcp-catalog/brands (for example "mcp/linear.svg").
func ReadBrandIcon(name string) ([]byte, string, error) {
	clean := path.Clean("/" + strings.TrimSpace(name))
	clean = strings.TrimPrefix(clean, "/")
	if clean == "" || clean == "." || strings.HasPrefix(clean, "..") {
		return nil, "", fs.ErrNotExist
	}
	data, err := fs.ReadFile(mcpcatalog.BrandsFS, path.Join("brands", clean))
	if err != nil {
		return nil, "", err
	}
	ct := mime.TypeByExtension(path.Ext(clean))
	if ct == "" {
		ct = "application/octet-stream"
	}
	return data, ct, nil
}

package proxy

import (
	"strings"

	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers/adapter"
)

// geminiStreamAction is the Gemini/Vertex URL action that signals a streamed
// response (clients hit ".../models/<model>:streamGenerateContent"). The leading
// colon is part of the match so unrelated paths that merely contain the word
// "streamGenerateContent" do not trigger a false positive.
const geminiStreamAction = ":streamGenerateContent"

// DetectStream reports whether the inbound request asks for a streamed response.
//
// Detection mirrors each wire format's own streaming convention:
//   - Gemini / Vertex signal streaming via the URL (":streamGenerateContent" in
//     the path or "alt=sse" in the query); their bodies carry no stream flag.
//   - OpenAI / Anthropic / Mistral / Responses carry "stream": true in the body.
//
// The URL signal takes precedence so a Gemini-style streaming request is honored
// even though its body has no flag; the explicit body flag is consulted only when
// no URL signal is present.
func DetectStream(req *infracontext.RequestContext) bool {
	if req == nil {
		return false
	}
	if strings.Contains(req.Path, geminiStreamAction) {
		return true
	}
	if req.Query != nil && req.Query.Get("alt") == "sse" {
		return true
	}
	if stream, explicit := adapter.RequestWantsStream(req.Body); explicit {
		return stream
	}
	return false
}

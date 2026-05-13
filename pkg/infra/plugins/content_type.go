package plugins

import (
	"strings"

	pluginTypes "github.com/NeuralTrust/TrustGate/pkg/infra/plugins/types"
	"github.com/NeuralTrust/TrustGate/pkg/types"
)

const (
	contentTypeHeader      = "Content-Type"
	contentTypeHeaderLower = "content-type"
)

func contentTypeSupported(supported []string, mediaType string) bool {
	if mediaType == "" || len(supported) == 0 {
		return true
	}

	for _, supportedType := range supported {
		supportedType = strings.TrimSpace(supportedType)
		switch {
		case supportedType == "", supportedType == pluginTypes.ContentTypeAny:
			return true
		case supportedType == mediaType, strings.EqualFold(supportedType, mediaType):
			return true
		case (supportedType == pluginTypes.ContentTypeApplicationJSON ||
			strings.EqualFold(supportedType, pluginTypes.ContentTypeApplicationJSON)) &&
			strings.HasSuffix(mediaType, "+json"):
			return true
		}
	}
	return false
}

func shouldExecuteForContentType(supported []string, mediaType string) bool {
	if mediaType == "" {
		return true
	}
	return contentTypeSupported(supported, mediaType)
}

func mediaTypeForStage(req *types.RequestContext, resp *types.ResponseContext) string {
	var raw string
	if req != nil && (req.Stage == pluginTypes.PreResponse || req.Stage == pluginTypes.PostResponse) && resp != nil {
		raw = headerValue(resp.Headers)
	}
	if raw == "" && req != nil {
		raw = headerValue(req.Headers)
	}
	if raw == "" {
		return ""
	}

	if idx := strings.IndexByte(raw, ';'); idx >= 0 {
		raw = raw[:idx]
	}
	return strings.ToLower(strings.TrimSpace(raw))
}

func headerValue(headers map[string][]string) string {
	if len(headers) == 0 {
		return ""
	}
	if values := headers[contentTypeHeader]; len(values) > 0 {
		return values[0]
	}
	if values := headers[contentTypeHeaderLower]; len(values) > 0 {
		return values[0]
	}
	for headerKey, values := range headers {
		if strings.EqualFold(headerKey, contentTypeHeader) && len(values) > 0 {
			return values[0]
		}
	}
	return ""
}

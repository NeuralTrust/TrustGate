package mcp

import "encoding/json"

const (
	modernProtocolVersion       = "2026-07-28"
	latestLegacyProtocolVersion = "2025-06-18"
)

var supportedProtocolVersions = []string{
	modernProtocolVersion,
	latestLegacyProtocolVersion,
	"2025-03-26",
	"2024-11-05",
}

var legacyProtocolVersions = map[string]struct{}{
	latestLegacyProtocolVersion: {},
	"2025-03-26":                {},
	"2024-11-05":                {},
}

type protocolEra uint8

type protocolVersionSignal struct {
	value   string
	present bool
	valid   bool
}

const (
	protocolEraLegacy protocolEra = iota
	protocolEraModern
)

func classifyEra(req rpcRequest, protocolHeader string) (protocolEra, *protocolError) {
	if req.Method == "initialize" || isLegacyProtocolVersion(protocolHeader) {
		return protocolEraLegacy, nil
	}

	metadataVersion := requestMetadataProtocolVersion(req.Params)
	if protocolHeader != "" && !isSupportedProtocolVersion(protocolHeader) {
		return protocolEraModern, unsupportedProtocolVersion(protocolHeader)
	}
	if metadataVersion.present && !metadataVersion.valid {
		return protocolEraModern, newProtocolError(codeInvalidParams, "protocolVersion must be a non-empty string")
	}
	if metadataVersion.present && !isSupportedProtocolVersion(metadataVersion.value) {
		return protocolEraModern, unsupportedProtocolVersion(metadataVersion.value)
	}
	if protocolHeader == modernProtocolVersion || metadataVersion.value == modernProtocolVersion {
		return protocolEraModern, nil
	}
	return protocolEraLegacy, nil
}

func isLegacyProtocolVersion(version string) bool {
	_, ok := legacyProtocolVersions[version]
	return ok
}

func isSupportedProtocolVersion(version string) bool {
	return version == modernProtocolVersion || isLegacyProtocolVersion(version)
}

func requestMetadataProtocolVersion(params json.RawMessage) protocolVersionSignal {
	paramsObject, ok := decodeObject(params)
	if !ok {
		return protocolVersionSignal{}
	}
	metadataObject, ok := decodeObject(paramsObject["_meta"])
	if !ok {
		return protocolVersionSignal{}
	}
	rawVersion, ok := metadataObject["io.modelcontextprotocol/protocolVersion"]
	if !ok {
		return protocolVersionSignal{}
	}
	var version string
	if err := json.Unmarshal(rawVersion, &version); err != nil || version == "" {
		return protocolVersionSignal{present: true}
	}
	return protocolVersionSignal{value: version, present: true, valid: true}
}

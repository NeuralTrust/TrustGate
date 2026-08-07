package mcp

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/gofiber/fiber/v2"
)

const (
	codeHeaderMismatch             = -32020
	codeUnsupportedProtocolVersion = -32022
	base64SentinelPrefix           = "=?base64?"
	base64SentinelSuffix           = "?="
)

type protocolError struct {
	code    int
	status  int
	message string
	data    any
}

type modernRequestHeaders struct {
	protocolVersion string
	method          string
	name            string
	hasToolParam    bool
}

type unsupportedProtocolVersionData struct {
	Supported []string `json:"supported"`
	Requested string   `json:"requested"`
}

func validateModernRequest(req rpcRequest, headers modernRequestHeaders) *protocolError {
	if req.JSONRPC != "2.0" || req.Method == "" {
		return newProtocolError(codeInvalidRequest, "invalid request")
	}
	if !validModernRequestID(req.ID) {
		return newProtocolError(codeInvalidRequest, "invalid request")
	}

	params, ok := decodeObject(req.Params)
	if !ok {
		return newProtocolError(codeInvalidParams, "params must be an object")
	}
	metadataRaw, ok := params["_meta"]
	if !ok {
		return headerMismatch("request protocol metadata is required")
	}
	metadata, ok := decodeObject(metadataRaw)
	if !ok {
		return newProtocolError(codeInvalidParams, "params._meta must be an object")
	}

	versionRaw, ok := metadata["io.modelcontextprotocol/protocolVersion"]
	if !ok {
		return headerMismatch("MCP-Protocol-Version metadata is required")
	}
	var version string
	if err := json.Unmarshal(versionRaw, &version); err != nil || version == "" {
		return newProtocolError(codeInvalidParams, "protocolVersion must be a non-empty string")
	}
	if !isSupportedProtocolVersion(version) {
		return unsupportedProtocolVersion(version)
	}
	if _, ok := decodeObject(metadata["io.modelcontextprotocol/clientCapabilities"]); !ok {
		return newProtocolError(codeInvalidParams, "clientCapabilities must be an object")
	}
	if headers.hasToolParam {
		return headerMismatch("Mcp-Param-* headers are not supported")
	}
	if headers.protocolVersion == "" || headers.protocolVersion != version {
		return headerMismatch("MCP-Protocol-Version header does not match request metadata")
	}
	if headers.method == "" || headers.method != req.Method {
		return headerMismatch("Mcp-Method header does not match request method")
	}

	sourceField := ""
	switch req.Method {
	case "tools/call", "prompts/get":
		sourceField = "name"
	case "resources/read":
		sourceField = "uri"
	}
	if sourceField == "" {
		return nil
	}

	var sourceValue string
	if err := json.Unmarshal(params[sourceField], &sourceValue); err != nil || sourceValue == "" {
		return newProtocolError(codeInvalidParams, fmt.Sprintf("%s requires params.%s", req.Method, sourceField))
	}
	decodedName, ok := decodeHeaderValue(headers.name)
	if headers.name == "" || !ok || decodedName != sourceValue {
		return headerMismatch("Mcp-Name header does not match request params")
	}
	return nil
}

func validModernRequestID(id json.RawMessage) bool {
	if len(id) == 0 {
		return true
	}
	decoder := json.NewDecoder(bytes.NewReader(id))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return false
	}
	switch value.(type) {
	case nil, string, json.Number:
		return true
	default:
		return false
	}
}

func modernHeaders(c *fiber.Ctx) modernRequestHeaders {
	headers := modernRequestHeaders{
		protocolVersion: c.Get("MCP-Protocol-Version"),
		method:          c.Get("Mcp-Method"),
		name:            c.Get("Mcp-Name"),
	}
	c.Request().Header.VisitAll(func(name, _ []byte) {
		if strings.HasPrefix(strings.ToLower(string(name)), "mcp-param-") {
			headers.hasToolParam = true
		}
	})
	return headers
}

func decodeObject(raw json.RawMessage) (map[string]json.RawMessage, bool) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		return nil, false
	}
	return object, true
}

func decodeHeaderValue(value string) (string, bool) {
	if strings.HasPrefix(value, base64SentinelPrefix) {
		if !strings.HasSuffix(value, base64SentinelSuffix) {
			return "", false
		}
		payload := strings.TrimSuffix(strings.TrimPrefix(value, base64SentinelPrefix), base64SentinelSuffix)
		decoded, err := base64.StdEncoding.DecodeString(payload)
		if err != nil || !utf8.Valid(decoded) || base64.StdEncoding.EncodeToString(decoded) != payload {
			return "", false
		}
		return string(decoded), true
	}
	if !plainHeaderValue(value) {
		return "", false
	}
	return value, true
}

func plainHeaderValue(value string) bool {
	if value == "" || value[0] == ' ' || value[0] == '\t' || value[len(value)-1] == ' ' || value[len(value)-1] == '\t' {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] != '\t' && (value[i] < 0x20 || value[i] > 0x7e) {
			return false
		}
	}
	return true
}

func newProtocolError(code int, message string) *protocolError {
	return &protocolError{code: code, status: fiber.StatusBadRequest, message: message}
}

func headerMismatch(message string) *protocolError {
	return newProtocolError(codeHeaderMismatch, "Header mismatch: "+message)
}

func unsupportedProtocolVersion(requested string) *protocolError {
	err := newProtocolError(codeUnsupportedProtocolVersion, "Unsupported protocol version")
	err.data = unsupportedProtocolVersionData{
		Supported: append([]string(nil), supportedProtocolVersions...),
		Requested: requested,
	}
	return err
}

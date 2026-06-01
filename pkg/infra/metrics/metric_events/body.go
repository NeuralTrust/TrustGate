package metric_events

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
)

const (
	multipartPlaceholder = `{"_multipart": true}`
	truncatedSuffix      = "...[truncated]"

	// maxSanitizedBodyBytes caps the body representation stored in an event so a
	// large payload cannot produce an oversized Kafka message or blow up memory.
	maxSanitizedBodyBytes = 64 * 1024
	// maxMultipartFieldValueBytes caps the captured value of a multipart form field.
	maxMultipartFieldValueBytes = 256
)

// sanitizeBody returns a loggable representation of a request/response body.
// Multipart payloads are reduced to their field names and file metadata so raw
// file contents never reach an exporter.
func sanitizeBody(body []byte, headers map[string][]string) string {
	if len(body) == 0 {
		return ""
	}

	contentType := lookupHeader(headers, "Content-Type")
	if contentType == "" {
		return capBody(body)
	}

	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return capBody(body)
	}

	if mediaType == "multipart/form-data" {
		return extractMultipartFileNames(body, params["boundary"])
	}

	return capBody(body)
}

func capBody(body []byte) string {
	if len(body) <= maxSanitizedBodyBytes {
		return string(body)
	}
	return string(body[:maxSanitizedBodyBytes]) + truncatedSuffix
}

func extractMultipartFileNames(body []byte, boundary string) string {
	if boundary == "" {
		return multipartPlaceholder
	}

	reader := multipart.NewReader(bytes.NewReader(body), boundary)
	result := make(map[string]interface{})

	for {
		part, err := reader.NextPart()
		if err != nil {
			break
		}

		filename := part.FileName()
		fieldname := part.FormName()

		if filename != "" {
			result[fieldname] = map[string]string{
				"_type":    "file",
				"filename": filename,
			}
		} else if fieldname != "" {
			value, _ := io.ReadAll(io.LimitReader(part, maxMultipartFieldValueBytes+1))
			if len(value) > 0 {
				result[fieldname] = capMultipartValue(value)
			}
		}
		_ = part.Close()
	}

	if len(result) == 0 {
		return multipartPlaceholder
	}

	jsonBytes, err := json.Marshal(result)
	if err != nil {
		return multipartPlaceholder
	}

	return string(jsonBytes)
}

func capMultipartValue(value []byte) string {
	if len(value) > maxMultipartFieldValueBytes {
		return string(value[:maxMultipartFieldValueBytes]) + truncatedSuffix
	}
	return string(value)
}

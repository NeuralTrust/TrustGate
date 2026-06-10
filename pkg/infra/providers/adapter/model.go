package adapter

import (
	"encoding/json"
	"errors"
	"fmt"
)

const (
	modelKey   = "model"
	modelIDKey = "modelId"
)

var ErrModelNotAllowed = errors.New("model not allowed")

func EnforceModel(body []byte, allowedModels []string, defaultModel string) ([]byte, string, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return body, "", err
	}

	modelKeyName := modelKey
	modelRaw, ok := raw[modelKeyName]
	if !ok || modelRaw == nil {
		modelKeyName = modelIDKey
		modelRaw, ok = raw[modelKeyName]
	}
	if !ok || modelRaw == nil {
		if defaultModel != "" {
			b, err := json.Marshal(defaultModel)
			if err != nil {
				return body, defaultModel, nil
			}
			raw[modelKey] = b
			out, err := json.Marshal(raw)
			if err != nil {
				return body, defaultModel, nil
			}
			return out, defaultModel, nil
		}
		if len(allowedModels) > 0 {
			return body, "", fmt.Errorf("%w: request has no model and binding has no default", ErrModelNotAllowed)
		}
		return body, "", nil
	}

	var model string
	if err := json.Unmarshal(modelRaw, &model); err != nil {
		return body, "", err
	}

	if len(allowedModels) > 0 && !isAllowed(model, allowedModels) {
		return body, model, fmt.Errorf("%w: %q", ErrModelNotAllowed, model)
	}

	return body, model, nil
}

// ExtractModel returns the "model" or "modelId" field from a JSON body without modifying it.
func ExtractModel(body []byte) (string, error) {
	var probe struct {
		Model   string `json:"model"`
		ModelID string `json:"modelId"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return "", err
	}
	if probe.Model != "" {
		return probe.Model, nil
	}
	if probe.ModelID != "" {
		return probe.ModelID, nil
	}
	return probe.Model, nil
}

func isAllowed(model string, allowed []string) bool {
	for _, m := range allowed {
		if m == model {
			return true
		}
	}
	return false
}

func OverrideModel(body []byte, model string) []byte {
	if model == "" {
		return body
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return body
	}
	encoded, err := json.Marshal(model)
	if err != nil {
		return body
	}
	key := modelKey
	if _, ok := raw[modelKey]; !ok {
		if _, ok := raw[modelIDKey]; ok {
			key = modelIDKey
		}
	}
	raw[key] = encoded
	out, err := json.Marshal(raw)
	if err != nil {
		return body
	}
	return out
}

func StripModel(body []byte) []byte {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return body
	}
	if _, hasModel := raw[modelKey]; !hasModel {
		if _, hasModelID := raw[modelIDKey]; !hasModelID {
			return body
		}
	}
	delete(raw, modelKey)
	delete(raw, modelIDKey)
	out, err := json.Marshal(raw)
	if err != nil {
		return body
	}
	return out
}

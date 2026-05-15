package adapter

import "encoding/json"

const (
	modelKey   = "model"
	modelIDKey = "modelId"
)

// ValidateModel extracts the "model" or "modelId" field from body, checks it against
// allowedModels and, if not allowed, replaces it with defaultModel. It returns
// the (possibly modified) body and the chosen model name.
//
// When allowedModels is empty every model is accepted.
func ValidateModel(body []byte, allowedModels []string, defaultModel string) ([]byte, string, error) {
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
		// No model in the body; inject defaultModel so downstream providers
		// (e.g. Google, Bedrock) can extract it from the request body.
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
		return body, defaultModel, nil
	}

	var model string
	if err := json.Unmarshal(modelRaw, &model); err != nil {
		return body, "", err
	}

	if modelKeyName == modelIDKey {
		return body, model, nil
	}

	if len(allowedModels) > 0 && !isAllowed(model, allowedModels) {
		model = defaultModel
		b, err := json.Marshal(model)
		if err != nil {
			return body, model, err
		}
		raw[modelKeyName] = b
		out, err := json.Marshal(raw)
		if err != nil {
			return body, model, err
		}
		return out, model, nil
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

package adapter

import "encoding/json"

// ValidateModel extracts the "model" field from body, checks it against
// allowedModels and, if not allowed, replaces it with defaultModel. It returns
// the (possibly modified) body and the chosen model name.
//
// When allowedModels is empty every model is accepted.
func ValidateModel(body []byte, allowedModels []string, defaultModel string) ([]byte, string, error) {
	// Partially decode – we only touch the "model" key.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return body, "", err
	}

	modelRaw, ok := raw["model"]
	if !ok || modelRaw == nil {
		// No model in the body; inject defaultModel so downstream providers
		// (e.g. Google, Bedrock) can extract it from the request body.
		if defaultModel != "" {
			b, err := json.Marshal(defaultModel)
			if err != nil {
				return body, defaultModel, nil
			}
			raw["model"] = b
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

	if len(allowedModels) > 0 && !isAllowed(model, allowedModels) {
		model = defaultModel
		b, err := json.Marshal(model)
		if err != nil {
			return body, model, err
		}
		raw["model"] = b
		out, err := json.Marshal(raw)
		if err != nil {
			return body, model, err
		}
		return out, model, nil
	}

	return body, model, nil
}

// ExtractModel returns the "model" field from a JSON body without modifying it.
func ExtractModel(body []byte) (string, error) {
	var probe struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return "", err
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

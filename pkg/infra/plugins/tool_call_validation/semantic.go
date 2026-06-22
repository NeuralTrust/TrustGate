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

package tool_call_validation

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

const (
	semanticTimeout       = 30 * time.Second
	semanticInstruction   = "You are a security validator. Respond only with valid JSON."
	semanticAPIOption     = "responses"
	semanticDecisionDeny  = "deny"
	semanticDecisionAllow = "allow"
)

type semanticDecision struct {
	Decision  string `json:"decision"`
	Reasoning string `json:"reasoning"`
}

func evaluateSemantic(
	ctx context.Context,
	cfg *SemanticConfig,
	client providers.Client,
	toolCall adapter.CanonicalToolCall,
	userPrompt string,
	reasoning string,
) (string, string, error) {
	prompt := buildSemanticPrompt(toolCall, userPrompt, reasoning)
	body, err := json.Marshal(map[string]any{
		"model":        cfg.Model,
		"input":        prompt,
		"instructions": semanticInstruction,
		"stream":       false,
	})
	if err != nil {
		return "", "", fmt.Errorf("tool_call_validation: marshal semantic request: %w", err)
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, semanticTimeout)
	defer cancel()

	providerConfig := &providers.Config{
		Credentials: providers.Credentials{ApiKey: cfg.APIKey},
		Model:       cfg.Model,
		Options:     map[string]any{"api": semanticAPIOption},
	}

	responseBytes, err := client.Completions(timeoutCtx, providerConfig, body)
	if err != nil {
		return "", "", fmt.Errorf("tool_call_validation: semantic completion: %w", err)
	}

	content, err := extractSemanticContent(responseBytes)
	if err != nil {
		return "", "", err
	}

	decision, reason := parseSemanticDecision(content)
	return decision, reason, nil
}

func buildSemanticPrompt(toolCall adapter.CanonicalToolCall, userPrompt, reasoning string) string {
	args := toolCall.Arguments
	if args == "" {
		args = "{}"
	}

	prompt := fmt.Sprintf(`You are a security validator. Analyze if a tool call makes sense given the user's request.

User Request: %s

Tool Name: %s
Tool Arguments: %s`, userPrompt, toolCall.Name, args)

	if reasoning != "" {
		prompt += fmt.Sprintf(`

LLM Reasoning Summary: %s
This is what the LLM thought before selecting this tool. Consider this context when validating the tool selection.`, reasoning)
	}

	prompt += `

Respond with ONLY a JSON object in this exact format:
{
  "decision": "allow" or "deny",
  "reasoning": "brief explanation (max 100 words)"
}

Consider:
- Does the tool selection align with the user's intent?
- Are the arguments appropriate for the user's request?
- Is there any suspicious or malicious intent?
- Does the LLM's reasoning (if provided) support the tool selection?

Respond with JSON only:`

	return prompt
}

func extractSemanticContent(responseBytes []byte) (string, error) {
	var response map[string]any
	if err := json.Unmarshal(responseBytes, &response); err != nil {
		return "", fmt.Errorf("tool_call_validation: decode semantic response: %w", err)
	}

	if outputArray, ok := response["output"].([]any); ok {
		for _, outputItem := range outputArray {
			item, ok := outputItem.(map[string]any)
			if !ok {
				continue
			}
			contentArray, ok := item["content"].([]any)
			if !ok {
				continue
			}
			for _, contentItem := range contentArray {
				contentMap, ok := contentItem.(map[string]any)
				if !ok {
					continue
				}
				if text, ok := contentMap["text"].(string); ok && text != "" {
					return text, nil
				}
			}
		}
	}

	if output, ok := response["output"].(string); ok && output != "" {
		return output, nil
	}
	if content, ok := response["content"].(string); ok && content != "" {
		return content, nil
	}

	if choices, ok := response["choices"].([]any); ok && len(choices) > 0 {
		if choice, ok := choices[0].(map[string]any); ok {
			if message, ok := choice["message"].(map[string]any); ok {
				if content, ok := message["content"].(string); ok && content != "" {
					return content, nil
				}
			}
		}
	}

	return "", fmt.Errorf("tool_call_validation: unexpected semantic response format")
}

func parseSemanticDecision(response string) (string, string) {
	response = strings.TrimSpace(response)

	if strings.HasPrefix(response, "```json") {
		response = strings.TrimPrefix(response, "```json")
		response = strings.TrimSuffix(response, "```")
		response = strings.TrimSpace(response)
	} else if strings.HasPrefix(response, "```") {
		response = strings.TrimPrefix(response, "```")
		response = strings.TrimSuffix(response, "```")
		response = strings.TrimSpace(response)
	}

	var result semanticDecision
	if err := json.Unmarshal([]byte(response), &result); err != nil {
		return semanticDecisionAllow, ""
	}

	if result.Decision != semanticDecisionDeny {
		result.Decision = semanticDecisionAllow
	}

	return result.Decision, result.Reasoning
}

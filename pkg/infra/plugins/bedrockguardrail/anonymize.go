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

package bedrockguardrail

import (
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
)

func maskedText(out *bedrockruntime.ApplyGuardrailOutput) (string, bool) {
	if out == nil || len(out.Outputs) == 0 {
		return "", false
	}
	text := aws.ToString(out.Outputs[0].Text)
	if text == "" {
		return "", false
	}
	return text, true
}

func rewriteRequest(reg *adapter.Registry, format adapter.Format, creq *adapter.CanonicalRequest, msgIndex int, masked string) ([]byte, bool) {
	if reg == nil || creq == nil || msgIndex < 0 || msgIndex >= len(creq.Messages) {
		return nil, false
	}
	adp, err := reg.GetAdapter(format)
	if err != nil {
		return nil, false
	}
	creq.Messages[msgIndex].Content = masked
	body, err := adp.EncodeRequest(creq)
	if err != nil {
		return nil, false
	}
	return body, true
}

func rewriteResponse(reg *adapter.Registry, format adapter.Format, cresp *adapter.CanonicalResponse, masked string) ([]byte, bool) {
	if reg == nil || cresp == nil {
		return nil, false
	}
	adp, err := reg.GetAdapter(format)
	if err != nil {
		return nil, false
	}
	cresp.Content = masked
	body, err := adp.EncodeResponse(cresp)
	if err != nil {
		return nil, false
	}
	return body, true
}

func supportsReencode(reg *adapter.Registry, format adapter.Format) bool {
	if reg == nil {
		return false
	}
	_, err := reg.GetAdapter(format)
	return err == nil
}

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

package googlemodelarmor

import "github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"

// maskedText returns the de-identified text Model Armor produced for the SDP
// filter, i.e. the text Model Armor itself returned with PII masked, not any
// masking TrustGate computes on its own.
func maskedText(result *SanitizationResult) (string, bool) {
	if result == nil || result.FilterResults.SDP == nil || result.FilterResults.SDP.DeidentifyResult == nil {
		return "", false
	}
	data := result.FilterResults.SDP.DeidentifyResult.Data
	if data == nil || data.Text == "" {
		return "", false
	}
	return data.Text, true
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

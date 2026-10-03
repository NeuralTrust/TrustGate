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

package trafficlabel

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"time"
)

// Request is one chat request waiting to be labeled. It is what travels in the
// queue, so it carries everything the worker needs without reading the config.
type Request struct {
	GatewayID   string    `json:"gateway_id"`
	ConsumerID  string    `json:"consumer_id"`
	TraceID     string    `json:"trace_id"`
	Text        string    `json:"text"`
	TextHash    string    `json:"text_hash"`
	Labels      []Label   `json:"labels"`
	CatalogHash string    `json:"catalog_hash"`
	RegistryID  string    `json:"registry_id"`
	Model       string    `json:"model"`
	ReceivedAt  time.Time `json:"received_at"`
}

type RequestParams struct {
	GatewayID  string
	ConsumerID string
	TraceID    string
	Text       string
	Config     *Config
	Labels     []Label
	ReceivedAt time.Time
}

func NewRequest(p RequestParams) Request {
	labels := cloneLabels(p.Labels)
	req := Request{
		GatewayID:   p.GatewayID,
		ConsumerID:  p.ConsumerID,
		TraceID:     p.TraceID,
		Text:        p.Text,
		TextHash:    HashText(p.Text),
		Labels:      labels,
		CatalogHash: CatalogHash(labels),
		ReceivedAt:  p.ReceivedAt,
	}
	if p.Config != nil {
		req.RegistryID = p.Config.RegistryID
		req.Model = p.Config.Model
	}
	return req
}

func cloneLabels(labels []Label) []Label {
	if labels == nil {
		return nil
	}
	out := make([]Label, len(labels))
	for i, l := range labels {
		out[i] = l
		out[i].Examples = slices.Clone(l.Examples)
	}
	return out
}

func HashText(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

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

package topic

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"time"
)

// Request is one unit of classification work: the text taken from a gateway
// request plus what is needed to classify it and correlate the result.
type Request struct {
	GatewayID   string    `json:"gateway_id"`
	ConsumerID  string    `json:"consumer_id,omitempty"`
	TraceID     string    `json:"trace_id"`
	Text        string    `json:"text"`
	TextHash    string    `json:"text_hash"`
	Topics      []Topic   `json:"topics"`
	CatalogHash string    `json:"catalog_hash"`
	Threshold   *float64  `json:"threshold,omitempty"`
	ReceivedAt  time.Time `json:"received_at"`
}

// RequestParams carries what NewRequest needs to build a Request.
type RequestParams struct {
	GatewayID  string
	ConsumerID string
	TraceID    string
	Text       string
	Config     *Config
	ReceivedAt time.Time
}

// NewRequest builds a Request from the gateway config in force when the
// request arrived, deriving both hashes. The catalog is copied so a later
// config change cannot alter work already queued.
func NewRequest(p RequestParams) Request {
	var topics []Topic
	var threshold *float64
	if p.Config != nil {
		topics = slices.Clone(p.Config.Topics)
		if p.Config.Threshold != nil {
			v := *p.Config.Threshold
			threshold = &v
		}
	}
	return Request{
		GatewayID:   p.GatewayID,
		ConsumerID:  p.ConsumerID,
		TraceID:     p.TraceID,
		Text:        p.Text,
		TextHash:    HashText(p.Text),
		Topics:      topics,
		CatalogHash: CatalogHash(topics),
		Threshold:   threshold,
		ReceivedAt:  p.ReceivedAt,
	}
}

// HashText returns the hex SHA-256 of text.
func HashText(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

// CatalogHash returns a hash that is equal for catalogs holding the same
// topics, whatever their order: order does not change the scores.
func CatalogHash(topics []Topic) string {
	sorted := slices.Clone(topics)
	slices.SortFunc(sorted, func(a, b Topic) int {
		return cmp.Compare(a.Name, b.Name)
	})
	h := sha256.New()
	for _, t := range sorted {
		h.Write([]byte(t.Name))
		h.Write([]byte{0})
		h.Write([]byte(t.Definition))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

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

// Package topicclassifier runs the per-gateway topic classification off the
// request path: it takes prompts from incoming requests, queues them and has
// them classified against topic-guard.
package topicclassifier

import (
	"context"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/topic"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

// Queue hands classification requests to the process that classifies them.
//
//go:generate mockery --name=Queue --dir=. --output=./mocks --filename=queue_mock.go --case=underscore --with-expecter
type Queue interface {
	Enqueue(ctx context.Context, req topic.Request) error
}

// Classifier scores texts that share a catalog and threshold against
// topic-guard. Results are index-aligned with texts.
//
//go:generate mockery --name=Classifier --dir=. --output=./mocks --filename=classifier_mock.go --case=underscore --with-expecter
type Classifier interface {
	Classify(ctx context.Context, topics []topic.Topic, threshold *float64, texts []string) ([]topic.Classification, error)
	// ModelVersion identifies the model and calibration currently serving,
	// so cached results from an older one are not reused.
	ModelVersion(ctx context.Context) (string, error)
}

// Cache remembers classifications under topic.CacheKey. Both calls take a
// whole batch, so a batch costs one round trip to read and one to write.
//
//go:generate mockery --name=Cache --dir=. --output=./mocks --filename=cache_mock.go --case=underscore --with-expecter
type Cache interface {
	// GetMany returns the entries found; missing keys are left out.
	GetMany(ctx context.Context, keys []string) (map[string]topic.Classification, error)
	SetMany(ctx context.Context, entries map[string]topic.Classification) error
}

// Sink publishes the classification of a request.
//
//go:generate mockery --name=Sink --dir=. --output=./mocks --filename=sink_mock.go --case=underscore --with-expecter
type Sink interface {
	Publish(ctx context.Context, req topic.Request, cls topic.Classification) error
}

// Delivery is a queued request handed to the worker. Invalid deliveries could
// not be decoded or were trimmed from the stream: they are acknowledged and
// dropped. Deliveries counts every time the entry was handed out.
type Delivery struct {
	ID         string
	Request    topic.Request
	Deliveries int64
	Invalid    bool
}

// Stream is the consuming side of the classification queue. Entries stay
// pending until acknowledged, so a consumer that dies leaves them for
// Reclaim; a live one keeps its entries with Touch.
//
//go:generate mockery --name=Stream --dir=. --output=./mocks --filename=stream_mock.go --case=underscore --with-expecter
type Stream interface {
	Read(ctx context.Context, count int, block time.Duration) ([]Delivery, error)
	Reclaim(ctx context.Context, minIdle time.Duration, count int) ([]Delivery, error)
	// Ack marks entries as done and removes them, with the text they carry.
	Ack(ctx context.Context, ids ...string) error
	// Touch keeps entries this consumer still works on from being reclaimed.
	Touch(ctx context.Context, ids ...string) error
	// Trim drops entries older than the retention.
	Trim(ctx context.Context) error
}

// RequestDecoder turns a provider request body into its canonical form.
//
//go:generate mockery --name=RequestDecoder --dir=. --output=./mocks --filename=request_decoder_mock.go --case=underscore --with-expecter
type RequestDecoder interface {
	DecodeRequestFor(body []byte, providerFormat adapter.Format) (*adapter.CanonicalRequest, error)
}

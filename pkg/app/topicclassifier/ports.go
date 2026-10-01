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

package topicclassifier

import (
	"context"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/topic"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

//go:generate mockery --name=Queue --dir=. --output=./mocks --filename=queue_mock.go --case=underscore --with-expecter
type Queue interface {
	Enqueue(ctx context.Context, req topic.Request) error
}

//go:generate mockery --name=Classifier --dir=. --output=./mocks --filename=classifier_mock.go --case=underscore --with-expecter
type Classifier interface {
	Classify(ctx context.Context, topics []topic.Topic, threshold *float64, texts []string) ([]topic.Classification, error)
	ModelVersion(ctx context.Context) (string, error)
}

//go:generate mockery --name=Cache --dir=. --output=./mocks --filename=cache_mock.go --case=underscore --with-expecter
type Cache interface {
	GetMany(ctx context.Context, keys []string) (map[string]topic.Classification, error)
	SetMany(ctx context.Context, entries map[string]topic.Classification) error
}

//go:generate mockery --name=Sink --dir=. --output=./mocks --filename=sink_mock.go --case=underscore --with-expecter
type Sink interface {
	Publish(ctx context.Context, req topic.Request, cls topic.Classification) error
}

type Delivery struct {
	ID         string
	Request    topic.Request
	Deliveries int64
	Invalid    bool
}

//go:generate mockery --name=Stream --dir=. --output=./mocks --filename=stream_mock.go --case=underscore --with-expecter
type Stream interface {
	Read(ctx context.Context, count int, block time.Duration) ([]Delivery, error)
	Reclaim(ctx context.Context, minIdle time.Duration, count int) ([]Delivery, error)
	Ack(ctx context.Context, ids ...string) error
	Touch(ctx context.Context, ids ...string) error
	Trim(ctx context.Context) error
}

//go:generate mockery --name=RequestDecoder --dir=. --output=./mocks --filename=request_decoder_mock.go --case=underscore --with-expecter
type RequestDecoder interface {
	DecodeRequestFor(body []byte, providerFormat adapter.Format) (*adapter.CanonicalRequest, error)
}

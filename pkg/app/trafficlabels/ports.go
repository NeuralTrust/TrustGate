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

package trafficlabels

import (
	"context"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/trafficlabel"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

//go:generate mockery --name=Queue --dir=. --output=./mocks --filename=queue_mock.go --case=underscore --with-expecter
type Queue interface {
	Enqueue(ctx context.Context, req trafficlabel.Request) error
}

// ClassifyInput is one text to label against a consumer's label sets, with
// the registry and model that run the classification.
type ClassifyInput struct {
	GatewayID  string
	RegistryID string
	Model      string
	LabelSets  []trafficlabel.LabelSet
	Text       string
}

//go:generate mockery --name=Classifier --dir=. --output=./mocks --filename=classifier_mock.go --case=underscore --with-expecter
type Classifier interface {
	Classify(ctx context.Context, in ClassifyInput) (trafficlabel.Classification, error)
}

//go:generate mockery --name=Cache --dir=. --output=./mocks --filename=cache_mock.go --case=underscore --with-expecter
type Cache interface {
	GetMany(ctx context.Context, keys []string) (map[string]trafficlabel.Classification, error)
	SetMany(ctx context.Context, entries map[string]trafficlabel.Classification) error
}

//go:generate mockery --name=Sink --dir=. --output=./mocks --filename=sink_mock.go --case=underscore --with-expecter
type Sink interface {
	Publish(ctx context.Context, req trafficlabel.Request, cls trafficlabel.Classification) error
}

type Delivery struct {
	ID         string
	Request    trafficlabel.Request
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

// ConversationKey names the conversation buffer of one session as seen by one
// consumer of one gateway.
type ConversationKey struct {
	GatewayID  string
	ConsumerID string
	SessionID  string
}

// ConversationBuffer keeps the most recent user messages of a conversation
// whose requests only carry the new turn (OpenAI Responses continuations), so
// the labeling window can still span earlier turns. A miss returns no
// messages and no error.
//
//go:generate mockery --name=ConversationBuffer --dir=. --output=./mocks --filename=conversation_buffer_mock.go --case=underscore --with-expecter
type ConversationBuffer interface {
	Load(ctx context.Context, key ConversationKey) ([]string, error)
	Save(ctx context.Context, key ConversationKey, messages []string) error
}

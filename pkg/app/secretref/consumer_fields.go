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

package secretref

import (
	"context"

	"github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/secretref"
)

// ValuesResolver resolves the declared locations of an entity; the
// Materializer is one.
type ValuesResolver interface {
	Values(ctx context.Context, gatewayID ids.GatewayID, source string, uses []Use) []Resolved
}

var consumerEmbeddingPath = []string{"lb_config", "embedding_config", "auth"}

// ConsumerRefs lists the declared locations of c that hold a reference or
// embed one, and where c sends them: its embedding provider and model.
func ConsumerRefs(c *consumer.Consumer) EntityRefs {
	refs := EntityRefs{GatewayID: c.GatewayID, Entity: domain.EntityConsumer, ID: c.ID.String()}
	if c.LBConfig == nil || c.LBConfig.EmbeddingConfig == nil {
		return refs
	}
	e := c.LBConfig.EmbeddingConfig
	refs.Destination = e.Provider + "\x00" + e.Model
	if e.Auth == nil {
		return refs
	}
	for _, f := range []struct{ key, value string }{{"api_key", e.Auth.APIKey}, {"header_value", e.Auth.HeaderValue}} {
		path := append(append([]string(nil), consumerEmbeddingPath...), f.key)
		switch {
		case domain.IsRef(f.value):
			refs.Uses = append(refs.Uses, Use{Path: path, Raw: f.value})
		case domain.ContainsRef(f.value):
			refs.Embedded = append(refs.Embedded, Use{Path: path, Raw: f.value})
		}
	}
	return refs
}

// GatewayConsumers returns consumers with every one whose embedding
// credential is a reference replaced by a copy carrying the resolved value,
// or an empty one when it does not resolve. It records what the gateway's
// consumers use, so a change invalidates the gateway. The input consumers are
// never modified.
func GatewayConsumers(ctx context.Context, r ValuesResolver, gatewayID ids.GatewayID, consumers []*consumer.Consumer) []*consumer.Consumer {
	type owner struct {
		index int
		key   string
	}
	var uses []Use
	var owners []owner
	for i, c := range consumers {
		if c == nil {
			continue
		}
		for _, u := range ConsumerRefs(c).Uses {
			uses = append(uses, u)
			owners = append(owners, owner{index: i, key: u.Path[len(u.Path)-1]})
		}
	}
	resolved := r.Values(ctx, gatewayID, SourceConsumers, uses)
	if len(uses) == 0 {
		return consumers
	}
	out := append([]*consumer.Consumer(nil), consumers...)
	copied := map[int]bool{}
	for i, o := range owners {
		if !copied[o.index] {
			out[o.index] = copyConsumerEmbedding(consumers[o.index])
			copied[o.index] = true
		}
		auth := out[o.index].LBConfig.EmbeddingConfig.Auth
		switch o.key {
		case "api_key":
			auth.APIKey = resolved[i].Value
		case "header_value":
			auth.HeaderValue = resolved[i].Value
		}
	}
	return out
}

func copyConsumerEmbedding(c *consumer.Consumer) *consumer.Consumer {
	cp := *c
	lb := *c.LBConfig
	emb := *lb.EmbeddingConfig
	auth := *emb.Auth
	emb.Auth = &auth
	lb.EmbeddingConfig = &emb
	cp.LBConfig = &lb
	return &cp
}

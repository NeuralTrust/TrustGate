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

package bedrock

import (
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
)

func TestReferencedCredentialsReplaceTheirPooledClient(t *testing.T) {
	t.Parallel()
	c := &client{clientPool: &sync.Map{}}
	literal := providers.Credentials{AwsBedrock: &providers.AwsBedrock{AccessKey: "AKID", Region: "eu-west-1"}}
	c.storeClient(buildClientKey(literal), literal, &bedrockruntime.Client{})
	for i, digest := range []string{"d1", "d2", "d3"} {
		creds := providers.Credentials{PoolKey: "ref:reg-1:" + digest, AwsBedrock: &providers.AwsBedrock{AccessKey: "AKID", Region: "eu-west-1"}}
		key := buildClientKey(creds)
		if key == buildClientKey(literal) {
			t.Fatal("a referenced credential must not share the literal key")
		}
		c.storeClient(key, creds, &bedrockruntime.Client{})
		n := 0
		c.clientPool.Range(func(any, any) bool { n++; return true })
		if n != 2 {
			t.Fatalf("after rotation %d the pool holds %d clients, want 2 (one literal, one referenced)", i+1, n)
		}
	}
	other := providers.Credentials{PoolKey: "ref:reg-2:d1", AwsBedrock: &providers.AwsBedrock{Region: "eu-west-1"}}
	c.storeClient(buildClientKey(other), other, &bedrockruntime.Client{})
	n := 0
	c.clientPool.Range(func(any, any) bool { n++; return true })
	if n != 3 {
		t.Fatalf("another registry's referenced client must not evict: pool %d", n)
	}
}

func TestLiteralPoolKeyIsUnchanged(t *testing.T) {
	t.Parallel()
	creds := providers.Credentials{AwsBedrock: &providers.AwsBedrock{AccessKey: "AKID", Region: "eu-west-1", RoleARN: "arn"}}
	if got := buildClientKey(creds); got != ":AKID:eu-west-1:false:arn" {
		t.Fatalf("literal key = %q", got)
	}
}

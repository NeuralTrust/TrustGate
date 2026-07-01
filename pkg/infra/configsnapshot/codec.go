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

package configsnapshot

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/configsnapshot/readmodel"
	"github.com/NeuralTrust/TrustGate/pkg/configsync"
	snapshotpb "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot/proto"
	"google.golang.org/protobuf/proto"
)

type Codec struct{}

var _ configsync.SnapshotCodec[*readmodel.Snapshot] = Codec{}

func NewCodec() Codec { return Codec{} }

func (Codec) Encode(snapshot *readmodel.Snapshot) ([]byte, error) {
	if snapshot == nil {
		return nil, fmt.Errorf("configsnapshot: encode nil snapshot")
	}
	msg, err := toProto(snapshot.Data())
	if err != nil {
		return nil, err
	}
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("configsnapshot: marshal snapshot: %w", err)
	}
	return raw, nil
}

func (Codec) Decode(raw []byte) (*readmodel.Snapshot, error) {
	var msg snapshotpb.Snapshot
	if err := proto.Unmarshal(raw, &msg); err != nil {
		return nil, fmt.Errorf("configsnapshot: unmarshal snapshot: %w", err)
	}
	data, err := fromProto(&msg)
	if err != nil {
		return nil, err
	}
	return readmodel.Build(data), nil
}

func (Codec) Version(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func toProto(data readmodel.Data) (*snapshotpb.Snapshot, error) {
	return &snapshotpb.Snapshot{Version: data.Version}, nil
}

func fromProto(msg *snapshotpb.Snapshot) (readmodel.Data, error) {
	return readmodel.Data{Version: msg.GetVersion()}, nil
}

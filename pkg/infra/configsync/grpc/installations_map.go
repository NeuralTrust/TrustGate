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

package grpc

import (
	"fmt"
	"time"

	snapshotpb "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot/proto"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
)

// installationToProto maps a domain installation onto the wire form. Timestamps
// travel as Unix seconds; the id travels verbatim so the control-plane repository
// upserts the row the data plane already minted.
func installationToProto(in *installationdomain.Installation) *snapshotpb.Installation {
	if in == nil {
		return nil
	}
	msg := &snapshotpb.Installation{
		Id:           in.ID.String(),
		GatewayId:    in.GatewayID.String(),
		PrincipalSub: in.PrincipalSub,
		CatalogCode:  in.CatalogCode,
		Status:       string(in.Status),
		InstalledBy:  in.InstalledBy,
	}
	if len(in.Config) > 0 {
		msg.Config = make(map[string]string, len(in.Config))
		for k, v := range in.Config {
			msg.Config[k] = v
		}
	}
	if !in.CreatedAt.IsZero() {
		msg.CreatedAtUnix = in.CreatedAt.Unix()
	}
	if !in.UpdatedAt.IsZero() {
		msg.UpdatedAtUnix = in.UpdatedAt.Unix()
	}
	return msg
}

// installationFromProto rebuilds a domain installation from the wire form. It
// preserves the id and timestamps the sender minted; a missing id is generated
// so a malformed message never persists a zero-uuid row.
func installationFromProto(msg *snapshotpb.Installation) (*installationdomain.Installation, error) {
	if msg == nil {
		return nil, fmt.Errorf("installation message is nil")
	}
	gatewayID, err := ids.Parse[ids.GatewayKind](msg.GetGatewayId())
	if err != nil {
		return nil, fmt.Errorf("parse gateway id: %w", err)
	}
	id, err := ids.Parse[ids.InstallationKind](msg.GetId())
	if err != nil || id.IsNil() {
		generated, gerr := ids.NewV7[ids.InstallationKind]()
		if gerr != nil {
			return nil, fmt.Errorf("generate installation id: %w", gerr)
		}
		id = generated
	}
	var config map[string]string
	if len(msg.GetConfig()) > 0 {
		config = make(map[string]string, len(msg.GetConfig()))
		for k, v := range msg.GetConfig() {
			config[k] = v
		}
	}
	out := &installationdomain.Installation{
		ID:           id,
		GatewayID:    gatewayID,
		PrincipalSub: msg.GetPrincipalSub(),
		CatalogCode:  msg.GetCatalogCode(),
		Status:       installationdomain.Status(msg.GetStatus()),
		InstalledBy:  msg.GetInstalledBy(),
		Config:       config,
	}
	if ts := msg.GetCreatedAtUnix(); ts > 0 {
		out.CreatedAt = time.Unix(ts, 0).UTC()
	}
	if ts := msg.GetUpdatedAtUnix(); ts > 0 {
		out.UpdatedAt = time.Unix(ts, 0).UTC()
	}
	return out, nil
}

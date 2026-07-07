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

package events

func (e Event) MetadataView() Event {
	e.Request.Body = ""
	e.Response.Body = nil
	return e
}

func (e Event) SensibleView() Event {
	return Event{
		SchemaVersion: e.SchemaVersion,
		TraceID:       e.TraceID,
		GatewayID:     e.GatewayID,
		TeamID:        e.TeamID,
		OccurredOn:    e.OccurredOn,
		Request:       Request{Body: e.Request.Body},
		Response:      Response{Body: e.Response.Body},
	}
}

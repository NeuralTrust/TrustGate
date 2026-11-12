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

package registry

// A2AMethodKind is what an A2A method does, whatever its name in a version.
type A2AMethodKind string

// A2A method kinds.
const (
	A2AMethodSend         A2AMethodKind = "send"
	A2AMethodStream       A2AMethodKind = "stream"
	A2AMethodGet          A2AMethodKind = "get"
	A2AMethodCancel       A2AMethodKind = "cancel"
	A2AMethodSubscribe    A2AMethodKind = "subscribe"
	A2AMethodList         A2AMethodKind = "list"
	A2AMethodPush         A2AMethodKind = "push"
	A2AMethodExtendedCard A2AMethodKind = "extended_card"
)

var a2aMethodKinds = map[A2AProtocolVersion]map[string]A2AMethodKind{
	A2AVersion03: {
		"message/send":                        A2AMethodSend,
		"message/stream":                      A2AMethodStream,
		"tasks/get":                           A2AMethodGet,
		"tasks/cancel":                        A2AMethodCancel,
		"tasks/resubscribe":                   A2AMethodSubscribe,
		"tasks/pushNotificationConfig/set":    A2AMethodPush,
		"tasks/pushNotificationConfig/get":    A2AMethodPush,
		"tasks/pushNotificationConfig/list":   A2AMethodPush,
		"tasks/pushNotificationConfig/delete": A2AMethodPush,
		"agent/getAuthenticatedExtendedCard":  A2AMethodExtendedCard,
	},
	A2AVersion10: {
		"SendMessage":                      A2AMethodSend,
		"SendStreamingMessage":             A2AMethodStream,
		"GetTask":                          A2AMethodGet,
		"CancelTask":                       A2AMethodCancel,
		"SubscribeToTask":                  A2AMethodSubscribe,
		"ListTasks":                        A2AMethodList,
		"CreateTaskPushNotificationConfig": A2AMethodPush,
		"GetTaskPushNotificationConfig":    A2AMethodPush,
		"ListTaskPushNotificationConfigs":  A2AMethodPush,
		"DeleteTaskPushNotificationConfig": A2AMethodPush,
		"GetExtendedAgentCard":             A2AMethodExtendedCard,
	},
}

// A2AMethodKindOf returns the kind of method in version v, and false for a
// method the version does not define.
func A2AMethodKindOf(v A2AProtocolVersion, method string) (A2AMethodKind, bool) {
	k, ok := a2aMethodKinds[v][method]
	return k, ok
}

// Forwarded reports whether the gateway sends calls of kind k to the agent.
// The others are answered by the gateway and never reach it.
func (k A2AMethodKind) Forwarded() bool {
	switch k {
	case A2AMethodSend, A2AMethodStream, A2AMethodGet, A2AMethodCancel, A2AMethodSubscribe:
		return true
	}
	return false
}

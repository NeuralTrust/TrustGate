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

package client

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
)

type modernSubscriptionStream struct {
	body          io.ReadCloser
	reader        *bufio.Reader
	acknowledged  appmcp.ListChangedCapabilities
	maxEventBytes int
	idleTimeout   time.Duration
	closeOnce     sync.Once
}

func (s *modernSubscriptionStream) Acknowledged() appmcp.ListChangedCapabilities {
	return s.acknowledged
}

func (s *modernSubscriptionStream) Next(ctx context.Context) (appmcp.SubscriptionEvent, error) {
	message, err := s.nextMessage(ctx)
	if err != nil {
		return appmcp.SubscriptionEvent{}, err
	}
	event, terminal, err := decodeSubscriptionEvent(message)
	if err != nil {
		return appmcp.SubscriptionEvent{}, err
	}
	if terminal {
		return appmcp.SubscriptionEvent{}, appmcp.ErrSubscriptionTerminal
	}
	return event, nil
}

func (s *modernSubscriptionStream) Close() error {
	var err error
	s.closeOnce.Do(func() {
		err = s.body.Close()
	})
	return err
}

func (s *modernSubscriptionStream) nextMessage(ctx context.Context) ([]byte, error) {
	deadline := time.Now().Add(s.idleTimeout)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, appmcp.ErrSubscriptionIdle
		}
		frame, hasData, err := s.readFrameWithin(ctx, remaining)
		if err != nil {
			return nil, err
		}
		if hasData {
			return frame, nil
		}
	}
}

func (s *modernSubscriptionStream) readFrame(ctx context.Context) ([]byte, bool, error) {
	return s.readFrameWithin(ctx, s.idleTimeout)
}

func (s *modernSubscriptionStream) readFrameWithin(
	ctx context.Context,
	idleTimeout time.Duration,
) ([]byte, bool, error) {
	var idle atomic.Bool
	timer := time.AfterFunc(idleTimeout, func() {
		idle.Store(true)
		s.body.Close()
	})
	stopContext := context.AfterFunc(ctx, func() {
		s.body.Close()
	})
	defer timer.Stop()
	defer stopContext()

	var data bytes.Buffer
	sawFrame := false
	for {
		line, err := readBoundedSSELine(s.reader, s.maxEventBytes+len("data: ")+2)
		if err != nil {
			if ctx.Err() != nil {
				return nil, false, ctx.Err()
			}
			if idle.Load() {
				return nil, false, appmcp.ErrSubscriptionIdle
			}
			if errors.Is(err, io.EOF) {
				return nil, false, appmcp.ErrSubscriptionTerminal
			}
			if errors.Is(err, appmcp.ErrSubscriptionProtocol) {
				return nil, false, err
			}
			return nil, false, appmcp.ErrSubscriptionTransportClosed
		}
		line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
		if line == "" {
			if sawFrame {
				return data.Bytes(), data.Len() > 0, nil
			}
			continue
		}
		sawFrame = true
		if strings.HasPrefix(line, ":") {
			continue
		}
		field, value, found := strings.Cut(line, ":")
		if !found || field != "data" {
			continue
		}
		value = strings.TrimPrefix(value, " ")
		added := len(value)
		if data.Len() > 0 {
			added++
		}
		if added > s.maxEventBytes-data.Len() {
			return nil, false, fmt.Errorf("%w: SSE event data exceeds %d bytes", appmcp.ErrSubscriptionProtocol, s.maxEventBytes)
		}
		if data.Len() > 0 {
			data.WriteByte('\n')
		}
		data.WriteString(value)
	}
}

func readBoundedSSELine(reader *bufio.Reader, maxBytes int) (string, error) {
	var line bytes.Buffer
	for {
		part, err := reader.ReadSlice('\n')
		if len(part) > maxBytes-line.Len() {
			return "", fmt.Errorf("%w: SSE line exceeds %d bytes", appmcp.ErrSubscriptionProtocol, maxBytes)
		}
		line.Write(part)
		if err == nil {
			return line.String(), nil
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			if errors.Is(err, io.EOF) && line.Len() > 0 {
				return line.String(), nil
			}
			return "", err
		}
	}
}

type subscriptionWireMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
	Result  json.RawMessage `json:"result"`
	Error   json.RawMessage `json:"error"`
}

func decodeSubscriptionAcknowledgement(data []byte) (appmcp.ListChangedCapabilities, error) {
	message, err := decodeSubscriptionWireMessage(data)
	if err != nil {
		return appmcp.ListChangedCapabilities{}, err
	}
	if message.Method != "notifications/subscriptions/acknowledged" ||
		message.ID != nil ||
		message.Result != nil ||
		message.Error != nil {
		return appmcp.ListChangedCapabilities{}, fmt.Errorf("%w: first frame is not an acknowledgement", appmcp.ErrSubscriptionProtocol)
	}
	var params struct {
		Notifications map[string]bool `json:"notifications"`
	}
	if err := json.Unmarshal(message.Params, &params); err != nil || params.Notifications == nil {
		return appmcp.ListChangedCapabilities{}, fmt.Errorf("%w: malformed acknowledgement", appmcp.ErrSubscriptionProtocol)
	}
	if len(params.Notifications) > 3 {
		return appmcp.ListChangedCapabilities{}, fmt.Errorf("%w: acknowledgement contains an unknown kind", appmcp.ErrSubscriptionProtocol)
	}
	for kind := range params.Notifications {
		if _, ok := appmcp.BoundNotificationKind(kind); !ok {
			return appmcp.ListChangedCapabilities{}, fmt.Errorf("%w: acknowledgement contains an unknown kind", appmcp.ErrSubscriptionProtocol)
		}
	}
	return appmcp.ListChangedCapabilities{
		Tools:     params.Notifications[string(appmcp.NotificationToolsListChanged)],
		Prompts:   params.Notifications[string(appmcp.NotificationPromptsListChanged)],
		Resources: params.Notifications[string(appmcp.NotificationResourcesListChanged)],
	}, nil
}

func decodeSubscriptionEvent(data []byte) (appmcp.SubscriptionEvent, bool, error) {
	message, err := decodeSubscriptionWireMessage(data)
	if err != nil {
		return appmcp.SubscriptionEvent{}, false, err
	}
	if message.Result != nil {
		return appmcp.SubscriptionEvent{}, false, fmt.Errorf("%w: unexpected JSON-RPC result", appmcp.ErrSubscriptionProtocol)
	}
	if message.Error != nil {
		return appmcp.SubscriptionEvent{}, false, fmt.Errorf("%w: upstream JSON-RPC error", appmcp.ErrSubscriptionProtocol)
	}
	if message.ID != nil {
		return appmcp.SubscriptionEvent{}, false, fmt.Errorf("%w: notification contains an id", appmcp.ErrSubscriptionProtocol)
	}
	var kind appmcp.NotificationKind
	switch message.Method {
	case appmcp.NotificationToolsListChanged.Method():
		kind = appmcp.NotificationToolsListChanged
	case appmcp.NotificationPromptsListChanged.Method():
		kind = appmcp.NotificationPromptsListChanged
	case appmcp.NotificationResourcesListChanged.Method():
		kind = appmcp.NotificationResourcesListChanged
	default:
		return appmcp.SubscriptionEvent{}, false, fmt.Errorf("%w: disallowed notification method", appmcp.ErrSubscriptionProtocol)
	}
	return appmcp.SubscriptionEvent{Kind: kind}, false, nil
}

func decodeSubscriptionWireMessage(data []byte) (subscriptionWireMessage, error) {
	var message subscriptionWireMessage
	if err := json.Unmarshal(data, &message); err != nil {
		return subscriptionWireMessage{}, fmt.Errorf("%w: malformed JSON-RPC frame", appmcp.ErrSubscriptionProtocol)
	}
	if message.JSONRPC != "2.0" {
		return subscriptionWireMessage{}, fmt.Errorf("%w: invalid JSON-RPC version", appmcp.ErrSubscriptionProtocol)
	}
	return message, nil
}

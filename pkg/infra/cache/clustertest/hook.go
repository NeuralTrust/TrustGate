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

// Package clustertest emulates the slot rules of a cluster-mode Redis (for
// example AWS ElastiCache Serverless) on top of a single-node test server, so
// tests can prove a code path never sends keys of different slots in one
// command, script or MULTI block. It is meant for tests only.
package clustertest

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/redis/go-redis/v9"
)

// CrossSlotMessage is the error a cluster-mode server answers with.
const CrossSlotMessage = "CROSSSLOT Keys in request don't hash to the same slot"

// Slot returns the Redis Cluster hash slot of key (CRC16-XMODEM mod 16384),
// honouring the {hashtag} rule.
func Slot(key string) int {
	if start := strings.IndexByte(key, '{'); start >= 0 {
		if end := strings.IndexByte(key[start+1:], '}'); end > 0 {
			key = key[start+1 : start+1+end]
		}
	}
	var crc uint16
	for i := 0; i < len(key); i++ {
		crc ^= uint16(key[i]) << 8
		for bit := 0; bit < 8; bit++ {
			if crc&0x8000 != 0 {
				crc = crc<<1 ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}
	return int(crc % 16384)
}

// keys extracts the key arguments of a command.
func keys(cmd redis.Cmder) []string {
	args := cmd.Args()
	if len(args) == 0 {
		return nil
	}
	var raw []any
	switch strings.ToLower(fmt.Sprint(args[0])) {
	case "mget", "del", "unlink", "exists", "touch":
		raw = args[1:]
	case "eval", "evalsha":
		if len(args) > 3 {
			n, err := strconv.Atoi(fmt.Sprint(args[2]))
			if err == nil && n > 0 && len(args) >= 3+n {
				raw = args[3 : 3+n]
			}
		}
	case "multi", "exec", "discard", "scan", "ping", "script":
	default:
		if len(args) > 1 {
			raw = args[1:2]
		}
	}
	out := make([]string, len(raw))
	for i, k := range raw {
		out[i] = fmt.Sprint(k)
	}
	return out
}

func spansSlots(ks []string) bool {
	for _, k := range ks[min(1, len(ks)):] {
		if Slot(k) != Slot(ks[0]) {
			return true
		}
	}
	return false
}

// Hook rejects, like a cluster, any command or script whose keys span several
// slots and any MULTI/EXEC block whose commands' keys span several slots.
// Plain pipelines of single-key commands pass.
type Hook struct{}

var _ redis.Hook = Hook{}

func (Hook) DialHook(next redis.DialHook) redis.DialHook {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		return next(ctx, network, addr)
	}
}

func (Hook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if spansSlots(keys(cmd)) {
			cmd.SetErr(errors.New(CrossSlotMessage))
			return cmd.Err()
		}
		return next(ctx, cmd)
	}
}

func (Hook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		failed := false
		var block []string
		inTx := len(cmds) > 0 && strings.EqualFold(fmt.Sprint(cmds[0].Args()[0]), "multi")
		for _, cmd := range cmds {
			ks := keys(cmd)
			if spansSlots(ks) {
				cmd.SetErr(errors.New(CrossSlotMessage))
				failed = true
			}
			if inTx {
				block = append(block, ks...)
			}
		}
		if inTx && spansSlots(block) {
			failed = true
			for _, cmd := range cmds {
				cmd.SetErr(errors.New(CrossSlotMessage))
			}
		}
		if failed {
			return errors.New(CrossSlotMessage)
		}
		return next(ctx, cmds)
	}
}

// New wraps rdb with the cluster-slot hook and returns it.
func New(rdb *redis.Client) *redis.Client {
	rdb.AddHook(Hook{})
	return rdb
}

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

// Command bench-overhead measures the latency and CPU the proxy plane adds on
// top of an upstream, with no policy attached to the consumer.
//
//	bench-overhead mock      serve an OpenAI-compatible upstream that answers instantly
//	bench-overhead provision create a gateway, registry, consumer and api key through the admin API
//	bench-overhead run       drive the same load at the upstream directly and through the proxy
//
// scripts/bench/overhead.sh wires the three together against a local stack.
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "mock":
		err = runMock(os.Args[2:])
	case "provision":
		err = runProvision(os.Args[2:])
	case "run":
		err = runLoad(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "bench-overhead:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: bench-overhead mock|provision|run [flags]")
	os.Exit(2)
}

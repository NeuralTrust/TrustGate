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

package readmodel

type Data struct {
	Version string
}

type Snapshot struct {
	data Data
}

func Build(data Data) *Snapshot {
	return &Snapshot{data: data}
}

func (s *Snapshot) Data() Data {
	return s.data
}

func (s *Snapshot) Version() string {
	return s.data.Version
}

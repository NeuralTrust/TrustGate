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

package tooltransform

func mergePatch(target, patch map[string]interface{}) map[string]interface{} {
	if target == nil {
		target = make(map[string]interface{}, len(patch))
	}
	for k, v := range patch {
		if v == nil {
			delete(target, k)
			continue
		}
		patchObj, patchIsObj := v.(map[string]interface{})
		if patchIsObj {
			targetObj, targetIsObj := target[k].(map[string]interface{})
			if targetIsObj {
				target[k] = mergePatch(targetObj, patchObj)
			} else {
				target[k] = mergePatch(nil, patchObj)
			}
			continue
		}
		target[k] = v
	}
	return target
}

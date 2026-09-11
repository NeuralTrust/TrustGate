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

package errors

import "errors"

var (
	ErrNotFound       = errors.New("resource not found; verify the id and that it exists")
	ErrAlreadyExists  = errors.New("resource already exists; use a unique name/slug or update the existing resource")
	ErrConflict       = errors.New("resource conflict; refresh and retry with the latest state")
	ErrHasDependents  = errors.New("resource has dependents; remove or reassign dependent resources first")
	ErrValidation     = errors.New("validation failed; check the request body and try again")
	ErrInvalidConfig  = errors.New("invalid configuration; fix the config fields and retry")
	ErrBoot           = errors.New("boot failure")
	ErrCorruptData    = errors.New("corrupt persisted data")
	ErrResultTooLarge = errors.New("result set too large; narrow filters or reduce page size")
)
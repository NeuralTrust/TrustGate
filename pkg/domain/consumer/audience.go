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

package consumer

import "fmt"

type Audience string

const (
	AudienceApplication Audience = "application"
	AudiencePersonal    Audience = "personal"
)

// ParseAudience maps a stored or requested audience onto its in-memory form,
// where an application consumer holds the empty audience.
func ParseAudience(s string) (Audience, error) {
	switch Audience(s) {
	case "", AudienceApplication, AudiencePersonal:
		return Audience(s).canonical(), nil
	}
	return "", fmt.Errorf("%w: %q", ErrInvalidAudience, s)
}

func (a Audience) canonical() Audience {
	if a == AudienceApplication {
		return ""
	}
	return a
}

func (c *Consumer) IsPersonal() bool {
	return c.Audience == AudiencePersonal
}

func (c *Consumer) AudienceName() Audience {
	if c.Audience == "" {
		return AudienceApplication
	}
	return c.Audience
}

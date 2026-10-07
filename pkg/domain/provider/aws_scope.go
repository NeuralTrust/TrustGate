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

package provider

import (
	"regexp"
	"strings"
)

// The scope of an AWS resource: the partition, region and account an ARN names.
// A region is written into host names that signed requests go to, so every
// parser of a client-supplied ARN and every builder of an AWS URL checks it
// here, and nowhere else.
var (
	awsRegion  = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-\d+$`)
	awsAccount = regexp.MustCompile(`^\d{12}$`)
)

// ValidAWSRegion reports a well-formed AWS region name: us-east-1, cn-north-1,
// us-gov-west-1, us-iso-east-1.
func ValidAWSRegion(region string) bool { return awsRegion.MatchString(region) }

// ValidAWSAccount reports a 12-digit AWS account id.
func ValidAWSAccount(account string) bool { return awsAccount.MatchString(account) }

// ValidAWSScope reports whether partition, region and account can belong to one
// ARN: the partition is aws, aws-cn or aws-us-gov, the region is a region name of
// that partition, and the account is empty (a foundation model's ARN has none) or
// a 12-digit id.
func ValidAWSScope(partition, region, account string) bool {
	if !ValidAWSRegion(region) || (account != "" && !ValidAWSAccount(account)) {
		return false
	}
	switch partition {
	case "aws":
		return !strings.HasPrefix(region, "cn-") && !strings.HasPrefix(region, "us-gov-")
	case "aws-cn":
		return strings.HasPrefix(region, "cn-")
	case "aws-us-gov":
		return strings.HasPrefix(region, "us-gov-")
	}
	return false
}

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

package cache

import "github.com/redis/go-redis/v9"

func newUniversalClient(options *redis.Options, cluster bool) redis.UniversalClient {
	if !cluster {
		return redis.NewClient(options)
	}
	return redis.NewClusterClient(clusterOptions(options))
}

// clusterOptions carries every setting the standalone options define into the
// cluster options, which apply them to each node's client. A cluster has a
// single database, so DB has no counterpart.
func clusterOptions(options *redis.Options) *redis.ClusterOptions {
	return &redis.ClusterOptions{
		Addrs:                      []string{options.Addr},
		Dialer:                     options.Dialer,
		Username:                   options.Username,
		Password:                   options.Password,
		CredentialsProviderContext: options.CredentialsProviderContext,
		TLSConfig:                  options.TLSConfig,
		MaxRetries:                 options.MaxRetries,
		DialTimeout:                options.DialTimeout,
		ReadTimeout:                options.ReadTimeout,
		WriteTimeout:               options.WriteTimeout,
		ContextTimeoutEnabled:      options.ContextTimeoutEnabled,
		PoolSize:                   options.PoolSize,
		PoolTimeout:                options.PoolTimeout,
		MinIdleConns:               options.MinIdleConns,
		ConnMaxIdleTime:            options.ConnMaxIdleTime,
		ConnMaxLifetime:            options.ConnMaxLifetime,
	}
}

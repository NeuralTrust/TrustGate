# Delta for proxy-api-key-expiry

Change `llm-store` (RUN-1763), slice S0. New capability. The LLM proxy plane (`/<slug>/v1/*`) stops accepting API keys whose `expires_at` has passed. Today `Auth.IsExpired` is only called from `key_finder.live`, so `APIKeyIdentityResolver.Resolve` (`pkg/api/resolver/api_key_resolver.go`) and `apiKeyAttachedElsewhere` (`pkg/api/middleware/auth.go`) accept expired keys. This is the only behaviour change of the change that is visible in OSS.

## ADDED Requirements

### Requirement: An expired key does not authenticate on the LLM proxy plane

`APIKeyIdentityResolver.Resolve` MUST skip every auth for which `Auth.IsExpired(now)` is true, exactly as it skips a disabled auth. The expiry boundary MUST be the one `Auth.IsExpired` already defines: a key whose `expires_at` equals `now` is expired. An auth with no `expires_at`, or with `expires_at` in the future, MUST authenticate exactly as today.

An expired key MUST be indistinguishable from an unknown key: it MUST get the status an unknown key gets on the same consumer. On a consumer that has an `api_key` auth attached, that is 401.

#### Scenario: Expired key on its own consumer

- GIVEN consumer X with an enabled `api_key` auth whose `expires_at` is one second before `now`
- WHEN a request to `/<X slug>/v1/chat/completions` presents that key
- THEN the response is 401 and the upstream is not called

#### Scenario: Expiry boundary

- GIVEN an enabled `api_key` auth of consumer X with `expires_at` equal to `now`
- WHEN the key is presented on `/<X slug>/v1/chat/completions`
- THEN the response is 401

#### Scenario: Future or absent expiry

- GIVEN two enabled `api_key` auths of consumer X, one with `expires_at` one hour after `now` and one with no `expires_at`
- WHEN each key is presented on `/<X slug>/v1/chat/completions`
- THEN both requests authenticate and reach the upstream, as today

### Requirement: An expired key attached elsewhere answers 401, never 403

`apiKeyAttachedElsewhere` MUST ignore expired auths, so an expired key that is attached to another consumer of the gateway MUST NOT turn the 401 into a 403. A non-expired key attached to another consumer MUST keep getting 403, as today.

#### Scenario: Expired key of another consumer

- GIVEN consumers X and Y of one gateway, both with an `api_key` auth, and Y's key expired
- WHEN Y's key is presented on `/<X slug>/v1/chat/completions`
- THEN the response is 401, not 403

#### Scenario: Valid key of another consumer

- GIVEN the same consumers and Y's key not expired
- WHEN Y's key is presented on `/<X slug>/v1/chat/completions`
- THEN the response is 403, as today

### Requirement: The clock is injected

The resolver and the middleware MUST read the current time through an injected `func() time.Time`, defaulting to `time.Now().UTC()` in production wiring, so that tests fix `now` instead of sleeping.

#### Scenario: Fixed clock in a unit test

- GIVEN a resolver built with a clock that returns `2026-10-02T12:00:00Z` and a key with `expires_at = 2026-10-02T12:00:01Z`
- WHEN the key is resolved, and then resolved again after the clock is advanced to `2026-10-02T12:00:01Z`
- THEN the first resolution succeeds and the second fails with `ErrUnauthenticated`

### Requirement: The behaviour change is called out

The PR that ships this capability MUST carry a release note stating that application keys with a past `expires_at` stop working on `/<slug>/v1/*`. Rolling back this capability alone MUST be a revert of the expiry checks, with no data change.

#### Scenario: Release note present

- GIVEN the PR that adds the expiry checks
- WHEN its body is reviewed
- THEN it contains the release note about expired application keys on `/<slug>/v1/*`

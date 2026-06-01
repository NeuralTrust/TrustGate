# LLM Provider Adapters Specification

## Purpose

Provider clients, adapters, factories, and balancing behavior for non-streaming LLM forwarding.

## Requirements

### Requirement: Provider Client Contract

Provider clients MUST support non-streaming request execution and MUST return a normalized response contract containing status, headers or metadata, body, and usage when available.

#### Scenario: Provider returns success

- GIVEN a valid provider target and non-streaming request
- WHEN the request is executed
- THEN a normalized response with status, body, and available usage is returned

#### Scenario: Provider rejects request

- GIVEN a provider returns an error response
- WHEN the request is executed
- THEN the error response is exposed without being converted into a successful result

### Requirement: Adapter and Factory Selection

The adapter factory MUST select the provider adapter from target/provider configuration. Unsupported providers MUST fail before an upstream request is attempted.

#### Scenario: Supported provider

- GIVEN target configuration names a supported provider
- WHEN an adapter is requested
- THEN the matching adapter is returned for forwarding

#### Scenario: Unsupported provider

- GIVEN target configuration names an unsupported provider
- WHEN an adapter is requested
- THEN selection fails and no provider request is sent

### Requirement: Load Balancing Strategies

Load balancing MUST choose from healthy eligible targets using configured non-semantic strategies. Semantic load balancing, embeddings, embedding factories, and embedding repositories MUST NOT be required or activated in B.1.

#### Scenario: Healthy targets exist

- GIVEN multiple healthy eligible targets
- WHEN a non-semantic strategy selects a target
- THEN one eligible target is selected according to the configured strategy

#### Scenario: No eligible target exists

- GIVEN all targets are unavailable or ineligible
- WHEN forwarding requests a target
- THEN selection fails with a forwarding error and no provider request is sent

#### Scenario: Semantic strategy is deferred

- GIVEN B.1 provider load balancing is configured
- WHEN load balancing is configured
- THEN semantic provider selection and embedding-backed balancing are not activated

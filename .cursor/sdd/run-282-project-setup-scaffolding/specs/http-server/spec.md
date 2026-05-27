# HTTP Server Specification

## Purpose
Admin and proxy surfaces share request-id, panic recovery, structured logging, validated config.

## Requirements

### Requirement: Request ID Propagation
Every response MUST carry a request-id header. Inbound ids MUST be preserved; otherwise one MUST be generated.

#### Scenario: Preserved
GIVEN `X-Request-Id: abc`; WHEN response returns; THEN same id on response and logs.

#### Scenario: Generated
GIVEN no inbound id; WHEN response returns; THEN fresh id on response and logs.

### Requirement: Panic Recovery
Handler panics MUST be recovered as HTTP 500. Stack traces MUST NOT leak in the body.

#### Scenario: Normal
GIVEN handler returns normally; WHEN it runs; THEN response is its declared status.

#### Scenario: Recovered
GIVEN panicking handler; WHEN request reaches it; THEN 500 generic body, panic logged with request id.

### Requirement: Structured Access Logging
Every request MUST emit a structured log entry with method, path, status, latency, and request-id.

#### Scenario: Logged
GIVEN any served request; WHEN it completes; THEN one entry contains all five fields.

#### Scenario: Errored request
GIVEN handler returns 500; WHEN it completes; THEN entry still records all five fields.

### Requirement: Configuration Validation
Loader MUST validate required fields at boot; missing or invalid values MUST abort startup.

#### Scenario: Valid
GIVEN required fields present; WHEN gateway starts; THEN listeners bind.

#### Scenario: Missing
GIVEN required field absent; WHEN gateway starts; THEN exit non-zero before binding.

_Source Linear issues: RUN-328_

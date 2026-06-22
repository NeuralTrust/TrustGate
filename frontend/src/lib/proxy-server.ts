import "server-only";

// Base URL of the TrustGate proxy plane (the LLM routing endpoint). This is a
// different port/service than the admin API the rest of the dashboard talks to.
export function proxyBaseUrl(): string {
  return process.env.PROXY_API_URL ?? "http://localhost:8081";
}

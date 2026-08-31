#!/usr/bin/env node
/**
 * TrustGate + OpenAI Node.js SDK example.
 *
 * Point the standard OpenAI SDK at TrustGate's proxy plane.
 *
 * Prerequisites:
 *   - TrustGate running (make up)
 *   - Gateway, registry, and consumer configured
 *   - Environment variables set:
 *       CONSUMER_API_KEY - your consumer API key
 *       CONSUMER_SLUG - consumer slug (default: my-app)
 *       GATEWAY_SLUG - gateway slug (default: demo)
 *       PROXY_URL - proxy URL (default: http://localhost:8081)
 *
 * Usage:
 *   npm install
 *   export CONSUMER_API_KEY="..."
 *   npx tsx chat.ts
 */

import OpenAI from "openai";

const PROXY_URL = process.env.PROXY_URL ?? "http://localhost:8081";
const CONSUMER_SLUG = process.env.CONSUMER_SLUG ?? "my-app";
const GATEWAY_SLUG = process.env.GATEWAY_SLUG ?? "demo";
const CONSUMER_API_KEY = process.env.CONSUMER_API_KEY;

if (!CONSUMER_API_KEY) {
  throw new Error(
    "CONSUMER_API_KEY environment variable is required.\n" +
      "Run examples/curl-first-request/first-request.sh to create one."
  );
}

const client = new OpenAI({
  baseURL: `${PROXY_URL}/${CONSUMER_SLUG}/v1`,
  apiKey: "unused", // provider key lives in the gateway
  defaultHeaders: {
    "X-AG-Gateway-Slug": GATEWAY_SLUG,
    "X-AG-API-Key": CONSUMER_API_KEY,
  },
});

async function main() {
  const response = await client.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [
      { role: "system", content: "You are a helpful assistant." },
      { role: "user", content: "What is TrustGate in one sentence?" },
    ],
  });

  console.log(response.choices[0].message.content);
}

main();

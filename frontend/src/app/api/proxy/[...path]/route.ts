import { NextRequest, NextResponse } from "next/server";
import { proxyBaseUrl } from "@/lib/proxy-server";

export const dynamic = "force-dynamic";

// Header the proxy plane expects the consumer API key in (see backend
// pkg/api/middleware/auth.go HeaderAPIKey).
const API_KEY_HEADER = "X-AG-API-Key";

interface RouteContext {
  params: Promise<{ path: string[] }>;
}

// Forwards a playground request to the gateway proxy plane and streams the
// upstream response straight back, so SSE chat completions render token by token.
async function handler(req: NextRequest, ctx: RouteContext): Promise<NextResponse> {
  const { path } = await ctx.params;
  const target = `${proxyBaseUrl()}/${path.join("/")}${req.nextUrl.search}`;

  const headers: Record<string, string> = { "Content-Type": "application/json" };
  const apiKey = req.headers.get(API_KEY_HEADER);
  if (apiKey) headers[API_KEY_HEADER] = apiKey;

  const body = await req.text();

  try {
    const res = await fetch(target, {
      method: "POST",
      headers,
      body: body.length > 0 ? body : undefined,
      cache: "no-store",
    });
    return new NextResponse(res.body, {
      status: res.status,
      headers: { "Content-Type": res.headers.get("content-type") ?? "application/json" },
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : "proxy request failed";
    return NextResponse.json({ error: "bff_error", message }, { status: 502 });
  }
}

export const POST = handler;

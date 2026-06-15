import { NextRequest, NextResponse } from "next/server";
import { mintPlaygroundToken } from "@/lib/jwt";
import { proxyBaseUrl } from "@/lib/proxy-server";

export const dynamic = "force-dynamic";

// Header the proxy plane expects the playground token in (see backend
// pkg/api/resolver/playground_resolver.go HeaderPlaygroundToken).
const PLAYGROUND_TOKEN_HEADER = "X-AG-Playground-Token";

interface RouteContext {
  params: Promise<{ path: string[] }>;
}

// Forwards a playground request to the gateway proxy plane, authenticating with
// a server-minted playground token bound to the consumer slug (the first path
// segment of every proxy route), and streams the upstream response straight
// back so SSE chat completions render token by token. The token never reaches
// the browser.
async function handler(req: NextRequest, ctx: RouteContext): Promise<NextResponse> {
  const { path } = await ctx.params;
  const consumerSlug = path[0];
  if (!consumerSlug) {
    return NextResponse.json(
      { error: "bff_error", message: "missing consumer slug in path" },
      { status: 400 },
    );
  }
  const target = `${proxyBaseUrl()}/${path.join("/")}${req.nextUrl.search}`;

  const body = await req.text();

  try {
    const token = await mintPlaygroundToken(consumerSlug);
    const res = await fetch(target, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        [PLAYGROUND_TOKEN_HEADER]: token,
      },
      body: body.length > 0 ? body : undefined,
      cache: "no-store",
    });
    return new NextResponse(res.body, {
      status: res.status,
      headers: { "Content-Type": res.headers.get("content-type") ?? "application/json" },
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : "playground request failed";
    return NextResponse.json({ error: "bff_error", message }, { status: 502 });
  }
}

export const POST = handler;

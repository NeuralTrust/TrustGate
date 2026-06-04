import { NextRequest, NextResponse } from "next/server";
import { adminFetch } from "@/lib/admin-server";

export const dynamic = "force-dynamic";

interface RouteContext {
  params: Promise<{ path: string[] }>;
}

async function proxy(req: NextRequest, ctx: RouteContext): Promise<NextResponse> {
  const { path } = await ctx.params;
  const target = "/" + path.join("/");
  const search = req.nextUrl.search;

  const hasBody = req.method !== "GET" && req.method !== "DELETE";
  let body: string | null = null;
  if (hasBody) {
    const raw = await req.text();
    body = raw.length > 0 ? raw : null;
  }

  try {
    const result = await adminFetch(target, { method: req.method, body, search });
    if (result.status === 204 || result.body.length === 0) {
      return new NextResponse(null, { status: result.status });
    }
    return new NextResponse(result.body, {
      status: result.status,
      headers: { "Content-Type": result.contentType },
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : "upstream request failed";
    return NextResponse.json({ error: "bff_error", message }, { status: 502 });
  }
}

export const GET = proxy;
export const POST = proxy;
export const PUT = proxy;
export const PATCH = proxy;
export const DELETE = proxy;

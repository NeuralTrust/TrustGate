import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { checkApiRequest } from "@/lib/request-guard";

export function proxy(req: NextRequest): NextResponse {
  const result = checkApiRequest(req.method, req.headers);
  if (!result.ok) {
    return NextResponse.json(
      { error: result.error, message: result.message },
      { status: result.status },
    );
  }
  return NextResponse.next();
}

export const config = {
  matcher: "/api/:path*",
};

const STATE_CHANGING_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

export interface HeaderReader {
  get(name: string): string | null;
}

export type GuardResult =
  | { ok: true }
  | { ok: false; status: 403 | 415; error: string; message: string };

function isSameOrigin(headers: HeaderReader): boolean {
  // Browsers that send Fetch Metadata state the relationship directly.
  const fetchSite = headers.get("sec-fetch-site");
  if (fetchSite !== null) {
    return fetchSite === "same-origin";
  }

  const origin = headers.get("origin");
  // Same precedence as the Next.js Server Actions origin check.
  const host = headers.get("x-forwarded-host") ?? headers.get("host");
  if (!origin || !host) {
    return false;
  }
  try {
    return new URL(origin).host === host;
  } catch {
    return false;
  }
}

function isJsonContentType(headers: HeaderReader): boolean {
  const contentType = headers.get("content-type");
  if (!contentType) {
    return false;
  }
  const mediaType = contentType.split(";", 1)[0] ?? "";
  return mediaType.trim().toLowerCase() === "application/json";
}

// Decides whether a request to the dashboard's /api routes may proceed.
// State-changing requests must come from the dashboard's own origin and carry a
// JSON content type, which a cross-site page cannot send without a CORS preflight.
export function checkApiRequest(method: string, headers: HeaderReader): GuardResult {
  if (!STATE_CHANGING_METHODS.has(method.toUpperCase())) {
    return { ok: true };
  }
  if (!isSameOrigin(headers)) {
    return {
      ok: false,
      status: 403,
      error: "forbidden_origin",
      message: "cross-origin requests are not allowed",
    };
  }
  if (!isJsonContentType(headers)) {
    return {
      ok: false,
      status: 415,
      error: "unsupported_media_type",
      message: "Content-Type must be application/json",
    };
  }
  return { ok: true };
}

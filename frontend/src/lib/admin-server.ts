import "server-only";
import { mintAdminToken } from "@/lib/jwt";

export function adminBaseUrl(): string {
  return process.env.ADMIN_API_URL ?? "http://localhost:8080";
}

export interface AdminResult {
  status: number;
  body: string;
  contentType: string;
}

export async function adminFetch(
  path: string,
  init: { method: string; body?: BodyInit | null; search?: string },
): Promise<AdminResult> {
  const token = await mintAdminToken();
  const url = `${adminBaseUrl()}${path}${init.search ?? ""}`;

  const headers: Record<string, string> = {
    Authorization: `Bearer ${token}`,
  };
  if (init.body != null) {
    headers["Content-Type"] = "application/json";
  }

  const res = await fetch(url, {
    method: init.method,
    headers,
    body: init.body ?? undefined,
    cache: "no-store",
  });

  const body = await res.text();
  return {
    status: res.status,
    body,
    contentType: res.headers.get("content-type") ?? "application/json",
  };
}

export async function adminJson<T>(path: string): Promise<T> {
  const res = await adminFetch(path, { method: "GET" });
  if (res.status >= 400) {
    throw new Error(`admin request failed (${res.status}): ${res.body}`);
  }
  return JSON.parse(res.body) as T;
}

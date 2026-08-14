import "server-only";
import { cookies } from "next/headers";
import { adminJson } from "@/lib/admin-server";
import type { Gateway, ListResponse } from "@/lib/types";

export const ACTIVE_GATEWAY_COOKIE = "ag_active_gateway";

/** httpio.MaxSize — the API clamps any larger `size` down to this. */
const MAX_PAGE_SIZE = 200;

export async function getActiveGatewayId(): Promise<string | null> {
  const store = await cookies();
  return store.get(ACTIVE_GATEWAY_COOKIE)?.value ?? null;
}

// The switcher needs every gateway the token can see, and a page is capped, so
// this walks the pages instead of cutting the list off at the first one.
export async function listGateways(): Promise<Gateway[]> {
  const all: Gateway[] = [];
  for (let page = 1; ; page++) {
    const res = await adminJson<ListResponse<Gateway>>(
      `/v1/gateways?page=${page}&size=${MAX_PAGE_SIZE}`,
    );
    const items = res.items ?? [];
    all.push(...items);
    if (items.length < MAX_PAGE_SIZE || all.length >= (res.total ?? all.length)) break;
  }
  return all;
}

export async function resolveActiveGateway(): Promise<{
  gateways: Gateway[];
  active: Gateway | null;
}> {
  let gateways: Gateway[] = [];
  try {
    gateways = await listGateways();
  } catch (err) {
    console.error("[dashboard] failed to list gateways:", err);
    return { gateways: [], active: null };
  }
  const cookieId = await getActiveGatewayId();
  const active =
    gateways.find((g) => g.id === cookieId) ?? gateways[0] ?? null;
  return { gateways, active };
}

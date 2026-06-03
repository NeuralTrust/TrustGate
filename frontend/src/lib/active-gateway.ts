import "server-only";
import { cookies } from "next/headers";
import { adminJson } from "@/lib/admin-server";
import type { Gateway, ListResponse } from "@/lib/types";

export const ACTIVE_GATEWAY_COOKIE = "ag_active_gateway";

export async function getActiveGatewayId(): Promise<string | null> {
  const store = await cookies();
  return store.get(ACTIVE_GATEWAY_COOKIE)?.value ?? null;
}

export async function listGateways(): Promise<Gateway[]> {
  const res = await adminJson<ListResponse<Gateway>>("/v1/gateways?size=200");
  return res.items ?? [];
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

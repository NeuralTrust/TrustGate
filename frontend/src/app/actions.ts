"use server";

import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { adminFetch } from "@/lib/admin-server";
import { ACTIVE_GATEWAY_COOKIE } from "@/lib/active-gateway";
import type { Gateway } from "@/lib/types";

const COOKIE_OPTS = {
  httpOnly: true,
  sameSite: "lax" as const,
  path: "/",
  maxAge: 60 * 60 * 24 * 365,
};

export async function setActiveGateway(gatewayId: string): Promise<void> {
  const store = await cookies();
  store.set(ACTIVE_GATEWAY_COOKIE, gatewayId, COOKIE_OPTS);
}

export async function createGatewayAction(formData: FormData): Promise<{ error?: string }> {
  const name = String(formData.get("name") ?? "").trim();
  if (!name) {
    return { error: "Gateway name is required." };
  }

  const res = await adminFetch("/v1/gateways", {
    method: "POST",
    body: JSON.stringify({ name }),
  });

  if (res.status >= 400) {
    let message = `Failed to create gateway (${res.status}).`;
    try {
      const data = JSON.parse(res.body) as { error?: string; message?: string };
      message = data.message || data.error || message;
    } catch {
      message = `Failed to create gateway (${res.status}).`;
    }
    return { error: message };
  }

  const gateway = JSON.parse(res.body) as Gateway;
  const store = await cookies();
  store.set(ACTIVE_GATEWAY_COOKIE, gateway.id, COOKIE_OPTS);
  redirect("/dashboard/registries");
}

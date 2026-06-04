"use client";

import { createContext, useContext } from "react";
import type { Gateway } from "@/lib/types";

interface GatewayContextValue {
  gateways: Gateway[];
  active: Gateway;
}

const GatewayContext = createContext<GatewayContextValue | null>(null);

export function GatewayProvider({
  gateways,
  active,
  children,
}: GatewayContextValue & { children: React.ReactNode }) {
  return (
    <GatewayContext.Provider value={{ gateways, active }}>{children}</GatewayContext.Provider>
  );
}

export function useGateway(): GatewayContextValue {
  const ctx = useContext(GatewayContext);
  if (!ctx) throw new Error("useGateway must be used within GatewayProvider");
  return ctx;
}

export function useActiveGatewayId(): string {
  return useGateway().active.id;
}

"use client";

import { usePathname } from "next/navigation";
import { GatewaySwitcher } from "./gateway-switcher";

const titles: Record<string, string> = {
  registries: "Registries",
  consumers: "Consumers",
  auth: "Auth",
  policies: "Policies",
};

export function Topbar() {
  const pathname = usePathname();
  const segment = pathname.split("/")[2] ?? "registries";
  const title = titles[segment] ?? "Dashboard";

  return (
    <header className="sticky top-0 z-30 h-14 border-b border-border bg-bg/80 backdrop-blur-md">
      <div className="flex h-full items-center justify-between px-6">
        <h1 className="text-[15px] font-semibold tracking-tight text-fg">{title}</h1>
        <GatewaySwitcher />
      </div>
    </header>
  );
}

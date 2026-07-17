"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Server, Users, UsersRound, KeyRound, ShieldCheck, FlaskConical } from "lucide-react";
import { Logo } from "./logo";
import { cn } from "@/lib/cn";

const nav = [
  { href: "/dashboard/consumers", label: "Consumers", icon: Users },
  { href: "/dashboard/registries", label: "Registry", icon: Server },
  { href: "/dashboard/roles", label: "Roles", icon: UsersRound },
  { href: "/dashboard/policies", label: "Policies", icon: ShieldCheck },
  { href: "/dashboard/auth", label: "Auth", icon: KeyRound },
  { href: "/dashboard/playground", label: "Playground", icon: FlaskConical },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="fixed inset-y-0 left-0 w-60 border-r border-border bg-surface/60 flex flex-col">
      <div className="h-14 flex items-center px-5 border-b border-border">
        <Link href="/dashboard/registries">
          <Logo />
        </Link>
      </div>

      <nav className="flex-1 px-3 py-4">
        <p className="px-3 pb-2 text-[11px] font-medium uppercase tracking-wider text-faint">
          Configuration
        </p>
        <ul className="flex flex-col gap-0.5">
          {nav.map((item) => {
            const active = pathname.startsWith(item.href);
            const Icon = item.icon;
            return (
              <li key={item.href}>
                <Link
                  href={item.href}
                  className={cn(
                    "group flex items-center gap-2.5 rounded-(--radius) px-3 h-9 text-[13.5px] transition-colors",
                    active
                      ? "bg-surface-2 text-fg font-medium"
                      : "text-muted hover:text-fg hover:bg-surface-2/50",
                  )}
                >
                  <Icon
                    className={cn(
                      "h-4 w-4 transition-colors",
                      active ? "text-accent" : "text-faint group-hover:text-muted",
                    )}
                  />
                  {item.label}
                </Link>
              </li>
            );
          })}
        </ul>
      </nav>

      <div className="px-5 py-4 border-t border-border">
        <p className="text-[11px] text-faint">TrustGate Console</p>
      </div>
    </aside>
  );
}

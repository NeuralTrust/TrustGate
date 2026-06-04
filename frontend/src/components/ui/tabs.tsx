"use client";

import * as TabsPrimitive from "@radix-ui/react-tabs";
import { cn } from "@/lib/cn";

export const Tabs = TabsPrimitive.Root;

export function TabsList({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <TabsPrimitive.List className={cn("flex items-center gap-1 border-b border-border", className)}>
      {children}
    </TabsPrimitive.List>
  );
}

export function TabTrigger({ value, children }: { value: string; children: React.ReactNode }) {
  return (
    <TabsPrimitive.Trigger
      value={value}
      className={cn(
        "relative px-3 h-9 text-[13px] text-muted transition-colors outline-none",
        "data-[state=active]:text-fg hover:text-fg",
        "after:absolute after:inset-x-2 after:-bottom-px after:h-0.5 after:rounded-full after:bg-transparent",
        "data-[state=active]:after:bg-accent",
      )}
    >
      {children}
    </TabsPrimitive.Trigger>
  );
}

export function TabContent({ value, children, className }: { value: string; children: React.ReactNode; className?: string }) {
  return (
    <TabsPrimitive.Content value={value} className={cn("outline-none", className)}>
      {children}
    </TabsPrimitive.Content>
  );
}

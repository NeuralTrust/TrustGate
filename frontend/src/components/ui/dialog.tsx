"use client";

import * as DialogPrimitive from "@radix-ui/react-dialog";
import { X } from "lucide-react";
import { cn } from "@/lib/cn";

export const Dialog = DialogPrimitive.Root;
export const DialogTrigger = DialogPrimitive.Trigger;
export const DialogClose = DialogPrimitive.Close;

export function DialogContent({
  className,
  children,
  size = "md",
}: {
  className?: string;
  children: React.ReactNode;
  size?: "md" | "lg" | "xl";
}) {
  const widths = { md: "max-w-lg", lg: "max-w-2xl", xl: "max-w-3xl" };
  return (
    <DialogPrimitive.Portal>
      <DialogPrimitive.Overlay className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm animate-overlay" />
      <DialogPrimitive.Content
        className={cn(
          "fixed left-1/2 top-1/2 z-50 w-[calc(100vw-2rem)] -translate-x-1/2 -translate-y-1/2 animate-content",
          "bg-surface border border-border-strong rounded-(--radius-lg) shadow-2xl shadow-black/50",
          "max-h-[88vh] overflow-hidden flex flex-col",
          widths[size],
          className,
        )}
      >
        {children}
        <DialogPrimitive.Close className="absolute right-4 top-4 text-faint hover:text-fg transition-colors outline-none">
          <X className="h-4.5 w-4.5" />
        </DialogPrimitive.Close>
      </DialogPrimitive.Content>
    </DialogPrimitive.Portal>
  );
}

export function DialogHeader({ title, description }: { title: string; description?: string }) {
  return (
    <div className="px-6 pt-5 pb-4 border-b border-border">
      <DialogPrimitive.Title className="text-[15px] font-semibold text-fg">
        {title}
      </DialogPrimitive.Title>
      {description && (
        <DialogPrimitive.Description className="text-[13px] text-muted mt-1">
          {description}
        </DialogPrimitive.Description>
      )}
    </div>
  );
}

export function DialogBody({ className, children }: { className?: string; children: React.ReactNode }) {
  return <div className={cn("px-6 py-5 overflow-y-auto", className)}>{children}</div>;
}

export function DialogFooter({ children }: { children: React.ReactNode }) {
  return (
    <div className="px-6 py-4 border-t border-border flex items-center justify-end gap-2.5 bg-surface-2/40">
      {children}
    </div>
  );
}

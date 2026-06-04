"use client";

import { forwardRef } from "react";
import { Loader2 } from "lucide-react";
import { cn } from "@/lib/cn";

type Variant = "primary" | "secondary" | "ghost" | "danger" | "outline";
type Size = "sm" | "md" | "icon";

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
  loading?: boolean;
}

const variants: Record<Variant, string> = {
  primary:
    "bg-fg text-bg hover:bg-fg/90 disabled:bg-fg/40 disabled:text-bg/70 font-medium",
  secondary:
    "bg-elevated text-fg hover:bg-border-strong border border-border-strong",
  outline: "border border-border-strong text-fg hover:bg-surface-2",
  ghost: "text-muted hover:text-fg hover:bg-surface-2",
  danger: "bg-danger/15 text-danger hover:bg-danger/25 border border-danger/30",
};

const sizes: Record<Size, string> = {
  sm: "h-8 px-3 text-[13px] gap-1.5 rounded-(--radius-sm)",
  md: "h-9.5 px-4 text-sm gap-2 rounded-(--radius)",
  icon: "h-9 w-9 rounded-(--radius) justify-center",
};

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = "secondary", size = "md", loading, children, disabled, ...props }, ref) => {
    return (
      <button
        ref={ref}
        disabled={disabled || loading}
        className={cn(
          "inline-flex items-center justify-center whitespace-nowrap transition-colors duration-150 outline-none focus-visible:ring-2 focus-visible:ring-accent/60 disabled:cursor-not-allowed select-none",
          variants[variant],
          sizes[size],
          className,
        )}
        {...props}
      >
        {loading && <Loader2 className="h-4 w-4 animate-spin" />}
        {children}
      </button>
    );
  },
);
Button.displayName = "Button";

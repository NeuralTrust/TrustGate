import { cn } from "@/lib/cn";

export function LogoMark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 32 32" fill="none" className={cn("h-7 w-7", className)} aria-hidden>
      <rect x="1" y="1" width="30" height="30" rx="8" fill="#0e0e11" stroke="#2e2e36" />
      <path
        d="M16 7 L24 11.5 V20.5 L16 25 L8 20.5 V11.5 Z"
        stroke="#7c7cff"
        strokeWidth="1.6"
        strokeLinejoin="round"
        fill="rgba(124,124,255,0.08)"
      />
      <circle cx="16" cy="16" r="2.4" fill="#7c7cff" />
    </svg>
  );
}

export function Logo({ className }: { className?: string }) {
  return (
    <div className={cn("flex items-center gap-2.5", className)}>
      <LogoMark className="h-7 w-7" />
      <span className="text-[15px] font-semibold tracking-tight text-fg">
        AgentGateway
      </span>
    </div>
  );
}

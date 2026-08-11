import { cn } from "@/lib/cn";

export function LogoMark({ className }: { className?: string }) {
  return (
    <span className={cn("inline-flex h-7 w-7 overflow-hidden rounded-[7px]", className)}>
      <svg viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true" className="h-full w-full">
        <g clipPath="url(#ntClip)">
          <path fill="url(#ntGrad)" d="M32 0H0v32h32z" />
          <path
            fill="#fff"
            d="M18.092 20.06a.67.67 0 0 1-.55.3.7.7 0 0 1-.565-.286l-2.704-3.814-1.45 2.103 2.197 3.098a3.08 3.08 0 0 0 2.51 1.297h.038a3.06 3.06 0 0 0 2.502-1.342l8.02-11.477h-2.926z"
          />
          <path
            fill="#fff"
            d="M14.292 11.518a.63.63 0 0 1 .552.286l2.652 3.74 1.449-2.103-2.145-3.024a3.08 3.08 0 0 0-2.509-1.297h-.039a3.06 3.06 0 0 0-2.506 1.35L3.925 21.85l-.085.123h2.91l6.98-10.155a.68.68 0 0 1 .562-.3"
          />
        </g>
        <defs>
          <linearGradient id="ntGrad" x1="30.667" x2="6.667" y1="0" y2="32" gradientUnits="userSpaceOnUse">
            <stop stopColor="#03AFFF" />
            <stop offset="1" stopColor="#9B29FF" />
          </linearGradient>
          <clipPath id="ntClip">
            <path fill="#fff" d="M0 0h32v32H0z" />
          </clipPath>
        </defs>
      </svg>
    </span>
  );
}

export function Logo({ className }: { className?: string }) {
  return (
    <div className={cn("flex items-center gap-2.5", className)}>
      <LogoMark className="h-7 w-7" />
      <span className="text-[15px] font-semibold tracking-tight text-fg">NeuralTrust</span>
    </div>
  );
}

import { redirect } from "next/navigation";
import { resolveActiveGateway } from "@/lib/active-gateway";
import { OnboardingForm } from "@/components/onboarding-form";
import { Logo } from "@/components/layout/logo";

export const dynamic = "force-dynamic";

export default async function HomePage() {
  const { active } = await resolveActiveGateway();
  if (active) {
    redirect("/dashboard/registries");
  }

  return (
    <main className="relative min-h-screen flex items-center justify-center overflow-hidden">
      <div className="absolute inset-0 grid-noise opacity-60" />
      <div
        className="absolute -top-40 left-1/2 -translate-x-1/2 h-[420px] w-[720px] rounded-full blur-3xl"
        style={{ background: "radial-gradient(closest-side, rgba(124,124,255,0.12), transparent)" }}
      />

      <div className="relative w-full max-w-md px-6">
        <div className="flex flex-col items-center text-center mb-8">
          <Logo className="h-9 w-auto mb-6" />
          <h1 className="text-[22px] font-semibold tracking-tight text-fg">
            Welcome to AgentGateway
          </h1>
          <p className="text-[14px] text-muted mt-2 max-w-xs">
            Create your first gateway to start configuring registries, consumers, auth and policies.
          </p>
        </div>

        <div className="rounded-(--radius-lg) border border-border bg-surface/80 backdrop-blur p-6 shadow-2xl shadow-black/40">
          <OnboardingForm />
        </div>

        <p className="text-center text-[12px] text-faint mt-6">
          A gateway is an isolated environment for your routing configuration.
        </p>
      </div>
    </main>
  );
}

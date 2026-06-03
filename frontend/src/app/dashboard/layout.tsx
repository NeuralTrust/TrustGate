import { redirect } from "next/navigation";
import { resolveActiveGateway } from "@/lib/active-gateway";
import { GatewayProvider } from "@/components/layout/gateway-context";
import { Sidebar } from "@/components/layout/sidebar";
import { Topbar } from "@/components/layout/topbar";

export const dynamic = "force-dynamic";

export default async function DashboardLayout({ children }: { children: React.ReactNode }) {
  const { gateways, active } = await resolveActiveGateway();
  if (!active) {
    redirect("/");
  }

  return (
    <GatewayProvider gateways={gateways} active={active}>
      <Sidebar />
      <div className="pl-60">
        <Topbar />
        <main className="px-6 py-6 max-w-[1400px]">{children}</main>
      </div>
    </GatewayProvider>
  );
}

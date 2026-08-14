"use client";

import { useState } from "react";
import { RefreshCw, Radio } from "lucide-react";
import { useConfigSyncConnections, errorMessage } from "@/lib/hooks";
import { PageHeader } from "@/components/ui/page";
import { Button } from "@/components/ui/button";
import { Table, THead, TBody, TH, TR, TD } from "@/components/ui/table";
import {
  FilterSelect,
  ListToolbar,
  NoMatches,
  useListControls,
} from "@/components/ui/list-controls";
import { Badge, EmptyState, PageLoader, Dot, Mono } from "@/components/ui/misc";
import { cn } from "@/lib/cn";

const CONNECTED = "connected";

/**
 * Data-plane connections as the control plane last observed them. The endpoint
 * is not gateway-scoped and returns every connection without a pagination
 * envelope; its own `scope` param is an exact match, so the toolbar filters the
 * fetched list locally instead of re-requesting per keystroke.
 */
export function ConfigSyncView() {
  const controls = useListControls();
  const { data, isLoading, error, refetch } = useConfigSyncConnections();
  const connections = data ?? [];
  // Tracked separately from isFetching so the background poll does not put the
  // button in a loading state every few seconds.
  const [refreshing, setRefreshing] = useState(false);

  async function refresh() {
    setRefreshing(true);
    try {
      await refetch();
    } finally {
      setRefreshing(false);
    }
  }

  const scopes = Array.from(new Set(connections.map((c) => c.scope))).sort();
  const term = controls.search.trim().toLowerCase();
  const scopeFilter = controls.filters.scope ?? "";
  const stateFilter = controls.filters.state ?? "";
  const rows = connections
    .filter((c) => scopeFilter === "" || c.scope === scopeFilter)
    .filter((c) =>
      stateFilter === ""
        ? true
        : stateFilter === CONNECTED
          ? c.state === CONNECTED
          : c.state !== CONNECTED,
    )
    .filter(
      (c) =>
        term === "" ||
        c.instance_id.toLowerCase().includes(term) ||
        c.scope.toLowerCase().includes(term) ||
        c.applied_version.toLowerCase().includes(term),
    )
    // Most recently seen first: the interesting rows are the ones still talking.
    .sort((a, b) => timestamp(b.last_seen) - timestamp(a.last_seen));

  const connected = connections.filter((c) => c.state === CONNECTED).length;

  return (
    <div>
      <PageHeader
        description="Data planes that registered with this control plane over config-sync, with the configuration version each one has applied. State is what the control plane last observed — a disconnected instance may simply have been shut down. The list refreshes on its own every few seconds."
        action={
          <Button onClick={() => void refresh()} loading={refreshing}>
            <RefreshCw className="h-4 w-4" />
            Refresh
          </Button>
        }
      />

      {isLoading ? (
        <PageLoader />
      ) : error ? (
        <EmptyState
          icon={<Radio className="h-5 w-5" />}
          title="Could not load connections"
          description={errorMessage(error) ?? "The config-sync endpoint did not answer."}
          action={
            <Button variant="ghost" onClick={() => void refetch()}>
              Retry
            </Button>
          }
        />
      ) : connections.length === 0 ? (
        <EmptyState
          icon={<Radio className="h-5 w-5" />}
          title="No data planes connected"
          description="Once a data plane opens a config-sync stream against this control plane it shows up here."
        />
      ) : (
        <>
          <p className="mb-3 text-[13px] text-muted">
            {connected} connected · {connections.length - connected} disconnected
          </p>

          <ListToolbar controls={controls} placeholder="Search by instance, scope or version…">
            <FilterSelect
              label="Scope"
              value={scopeFilter}
              onChange={(v) => controls.setFilter("scope", v)}
            >
              <option value="">Any scope</option>
              {scopes.map((scope) => (
                <option key={scope} value={scope}>
                  {scope}
                </option>
              ))}
            </FilterSelect>
            <FilterSelect
              label="State"
              value={stateFilter}
              onChange={(v) => controls.setFilter("state", v)}
            >
              <option value="">Any state</option>
              <option value={CONNECTED}>Connected</option>
              <option value="disconnected">Disconnected</option>
            </FilterSelect>
          </ListToolbar>

          {rows.length === 0 ? (
            <NoMatches controls={controls} label="connections" />
          ) : (
            <Table>
              <THead>
                <TH>Instance</TH>
                <TH>Scope</TH>
                <TH>Applied version</TH>
                <TH>First seen</TH>
                <TH>Last seen</TH>
                <TH>State</TH>
              </THead>
              <TBody>
                {rows.map((c) => (
                  <TR key={`${c.scope}:${c.instance_id}`}>
                    <TD>
                      <Mono>{c.instance_id}</Mono>
                    </TD>
                    <TD>
                      <span className="text-[12px] text-muted">{c.scope || "—"}</span>
                    </TD>
                    <TD>
                      {c.applied_version ? (
                        <Badge tone="accent">{c.applied_version}</Badge>
                      ) : (
                        <span className="text-faint">—</span>
                      )}
                    </TD>
                    <TD>
                      <Timestamp value={c.first_seen} />
                    </TD>
                    <TD>
                      <Timestamp value={c.last_seen} />
                    </TD>
                    <TD>
                      <span
                        className={cn(
                          "inline-flex items-center gap-2 text-muted",
                          c.state === CONNECTED && "text-fg",
                        )}
                      >
                        <Dot active={c.state === CONNECTED} />
                        {c.state || "unknown"}
                      </span>
                    </TD>
                  </TR>
                ))}
              </TBody>
            </Table>
          )}
        </>
      )}
    </div>
  );
}

function Timestamp({ value }: { value: string }) {
  const at = timestamp(value);
  if (at <= 0) return <span className="text-faint">—</span>;
  return (
    <span className="text-[12px] text-muted" title={new Date(at).toLocaleString()}>
      {relative(at)}
    </span>
  );
}

// Go's zero time marshals as 0001-01-01T00:00:00Z, whose epoch is negative; the
// callers treat anything <= 0 as "never seen".
function timestamp(value: string): number {
  const at = new Date(value).getTime();
  return Number.isNaN(at) ? 0 : at;
}

function relative(at: number): string {
  const seconds = Math.max(0, Math.round((Date.now() - at) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

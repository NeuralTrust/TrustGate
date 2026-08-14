"use client";

import { useQuery, useMutation, useQueryClient, keepPreviousData } from "@tanstack/react-query";
import { api, gatewayScope } from "@/lib/admin-client";
import { useActiveGatewayId } from "@/components/layout/gateway-context";
import { useToast } from "@/components/ui/toast";
import { AdminApiError } from "@/lib/admin-client";
import type {
  ConfigSyncConnection,
  ConfigSyncConnectionsResponse,
  ListResponse,
  McpTool,
  McpToolsResponse,
  MCPServer,
  MCPServersResponse,
  Model,
  PlaygroundTrace,
  PolicyCatalog,
  PolicyCatalogGroup,
} from "@/lib/types";

/** httpio.MaxSize — the API clamps any larger `size` down to this. */
export const MAX_PAGE_SIZE = 200;

export type SortOrder = "asc" | "desc";

export interface ListQuery {
  page?: number;
  size?: number;
  search?: string;
  sort?: string;
  order?: SortOrder;
  /**
   * Entity-specific filters. Empty strings and undefined mean "no filter"; an
   * array repeats the key, which the CSV params (policy category/type) accept.
   */
  filters?: Record<string, string | string[] | undefined>;
}

function listQueryString(query: ListQuery): string {
  const params = new URLSearchParams();
  if (query.page && query.page > 1) params.set("page", String(query.page));
  if (query.size) params.set("size", String(Math.min(query.size, MAX_PAGE_SIZE)));
  const search = query.search?.trim();
  if (search) params.set("search", search);
  // The API answers 400 for an order without a sort field, so they travel together.
  if (query.sort) {
    params.set("sort", query.sort);
    params.set("order", query.order ?? "asc");
  }
  for (const [key, value] of Object.entries(query.filters ?? {})) {
    if (Array.isArray(value)) {
      for (const item of value) if (item) params.append(key, item);
    } else if (value) {
      params.set(key, value);
    }
  }
  const qs = params.toString();
  return qs ? `?${qs}` : "";
}

/**
 * One page of a resource, filtered and sorted by the API. Returns the envelope
 * (items + total) rather than bare items so the caller can render pagination.
 *
 * Registries are the exception: that endpoint takes only `name`, `page` and
 * `size`, so search/sort/filters are ignored there — use `useAllList` instead.
 */
export function usePagedList<T>(resource: string, query: ListQuery = {}) {
  const gatewayId = useActiveGatewayId();
  const qs = listQueryString(query);
  return useQuery({
    queryKey: [resource, gatewayId, "page", qs],
    queryFn: () => api.get<ListResponse<T>>(`${gatewayScope(gatewayId)}/${resource}${qs}`),
    // Keeps the current page on screen while the next one loads, so typing in
    // the search box does not flash an empty table.
    placeholderData: keepPreviousData,
  });
}

/**
 * Every item of a resource, for pickers and views that cross-reference ids.
 * A page is capped at MAX_PAGE_SIZE, so this walks the pages instead of
 * silently truncating a gateway that has more than that.
 */
export function useAllList<T>(resource: string) {
  const gatewayId = useActiveGatewayId();
  return useQuery({
    queryKey: [resource, gatewayId, "all"],
    queryFn: async (): Promise<T[]> => {
      const base = `${gatewayScope(gatewayId)}/${resource}`;
      const all: T[] = [];
      for (let page = 1; ; page++) {
        const res = await api.get<ListResponse<T>>(`${base}?page=${page}&size=${MAX_PAGE_SIZE}`);
        const items = res.items ?? [];
        all.push(...items);
        if (items.length < MAX_PAGE_SIZE || all.length >= (res.total ?? all.length)) break;
      }
      return all;
    },
  });
}

export function useCatalogQuery<T>(key: string, path: string, enabled = true) {
  return useQuery({
    queryKey: [key],
    queryFn: () => api.get<ListResponse<T>>(path),
    select: (data) => data.items ?? [],
    enabled,
    staleTime: 5 * 60 * 1000,
  });
}

export function usePolicyCatalog() {
  return useQuery({
    queryKey: ["policies-catalog"],
    queryFn: () => api.get<PolicyCatalog>("/v1/policies-catalog"),
    select: (data): PolicyCatalogGroup[] => data.groups ?? [],
    staleTime: 5 * 60 * 1000,
  });
}

/**
 * Naming a registry scopes the catalog to what its credentials can actually
 * invoke — on Bedrock that drops Marketplace and provisioned-only models, which
 * would otherwise be offered and fail at request time.
 */
export function useModelsCatalog(
  providerCode?: string,
  scope?: { gatewayId?: string; registryId?: string },
) {
  const params = new URLSearchParams();
  if (providerCode) params.set("provider", providerCode);
  if (scope?.gatewayId && scope?.registryId) {
    params.set("gateway_id", scope.gatewayId);
    params.set("registry_id", scope.registryId);
  }
  const query = params.toString();

  return useQuery({
    queryKey: ["models-catalog", providerCode ?? "all", scope?.registryId ?? "any"],
    queryFn: () => api.get<ListResponse<Model>>(`/v1/models-catalog${query ? `?${query}` : ""}`),
    select: (data): Model[] => data.items ?? [],
    enabled: providerCode !== "",
    staleTime: 5 * 60 * 1000,
  });
}

/**
 * Introspects the MCP server behind a registry. The endpoint answers 502 when
 * the upstream is unreachable, so the query fails fast instead of retrying — the
 * toolkit editor falls back to typing names by hand.
 */
export function useRegistryTools(registryId: string) {
  const gatewayId = useActiveGatewayId();
  return useQuery({
    queryKey: ["registry-tools", gatewayId, registryId],
    queryFn: () =>
      api.get<McpToolsResponse>(`${gatewayScope(gatewayId)}/registries/${registryId}/tools`),
    select: (data): McpTool[] => data.tools ?? [],
    enabled: registryId !== "",
    retry: false,
    staleTime: 60 * 1000,
  });
}

export function useMcpCatalog() {
  return useQuery({
    queryKey: ["mcp-servers-catalog"],
    queryFn: () => api.get<MCPServersResponse>("/v1/mcp-servers-catalog"),
    select: (data): MCPServer[] => data.mcp_servers ?? [],
    staleTime: 5 * 60 * 1000,
  });
}

/**
 * The metrics event the proxy recorded for a playground request, keyed by the
 * X-AG-Trace-Id it echoed back. The event is written after the response was
 * already streamed, so a fresh trace can 404 for a moment — hence the short
 * retry on 404 only. A 404 that persists means the TTL expired or the trace
 * store is disabled.
 */
export function usePlaygroundTrace(traceId: string, enabled = true) {
  return useQuery({
    queryKey: ["playground-trace", traceId],
    queryFn: () => api.get<PlaygroundTrace>(`/v1/playground/traces/${traceId}`),
    enabled: enabled && traceId !== "",
    retry: (failureCount, err) => failureCount < 3 && isNotFound(err),
    retryDelay: 700,
    staleTime: Infinity,
  });
}

/**
 * Data-plane sync connections. Not gateway-scoped and returned without a
 * pagination envelope. It answers "is this data plane online?", so it is polled
 * instead of cached.
 */
export function useConfigSyncConnections(scope = "") {
  return useQuery({
    queryKey: ["config-sync-connections", scope],
    queryFn: () =>
      api.get<ConfigSyncConnectionsResponse>(
        `/v1/config-sync/connections${scope ? `?scope=${encodeURIComponent(scope)}` : ""}`,
      ),
    select: (data): ConfigSyncConnection[] => data.items ?? [],
    refetchInterval: 15 * 1000,
    staleTime: 5 * 1000,
  });
}

export function useInvalidate() {
  const qc = useQueryClient();
  const gatewayId = useActiveGatewayId();
  return (resource: string) => qc.invalidateQueries({ queryKey: [resource, gatewayId] });
}

/** True when the API answered 404 — an expected outcome for expiring resources. */
export function isNotFound(err: unknown): boolean {
  return err instanceof AdminApiError && err.status === 404;
}

export function errorMessage(err: unknown): string | undefined {
  if (err instanceof AdminApiError) {
    return err.message && err.message !== err.code ? `${err.code}: ${err.message}` : err.code;
  }
  return err instanceof Error ? err.message : undefined;
}

export function useEntityMutations(resource: string, label: string) {
  const invalidate = useInvalidate();
  const { toast } = useToast();

  return useMutation({
    mutationFn: async (fn: () => Promise<unknown>) => fn(),
    onSuccess: () => {
      void invalidate(resource);
    },
    onError: (err) => {
      toast({ variant: "error", title: `${label} failed`, description: errorMessage(err) });
    },
  });
}

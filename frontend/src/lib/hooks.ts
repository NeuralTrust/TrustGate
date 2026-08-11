"use client";

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api, gatewayScope } from "@/lib/admin-client";
import { useActiveGatewayId } from "@/components/layout/gateway-context";
import { useToast } from "@/components/ui/toast";
import { AdminApiError } from "@/lib/admin-client";
import type {
  ListResponse,
  MCPServer,
  MCPServersResponse,
  Model,
  PolicyCatalog,
  PolicyCatalogGroup,
} from "@/lib/types";

export function useList<T>(resource: string) {
  const gatewayId = useActiveGatewayId();
  return useQuery({
    queryKey: [resource, gatewayId],
    queryFn: () =>
      api.get<ListResponse<T>>(`${gatewayScope(gatewayId)}/${resource}?size=200`),
    select: (data) => data.items ?? [],
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

export function useMcpCatalog() {
  return useQuery({
    queryKey: ["mcp-servers-catalog"],
    queryFn: () => api.get<MCPServersResponse>("/v1/mcp-servers-catalog"),
    select: (data): MCPServer[] => data.mcp_servers ?? [],
    staleTime: 5 * 60 * 1000,
  });
}

export function useInvalidate() {
  const qc = useQueryClient();
  const gatewayId = useActiveGatewayId();
  return (resource: string) => qc.invalidateQueries({ queryKey: [resource, gatewayId] });
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

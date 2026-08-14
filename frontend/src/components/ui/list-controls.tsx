"use client";

import { useEffect, useMemo, useState } from "react";
import { ArrowDown, ArrowDownUp, ArrowUp, ChevronLeft, ChevronRight, SearchX } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input, Select } from "@/components/ui/field";
import { EmptyState } from "@/components/ui/misc";
import { TH } from "@/components/ui/table";
import { cn } from "@/lib/cn";
import type { ListQuery, SortOrder } from "@/lib/hooks";

const PAGE_SIZES = [20, 50, 100, 200];
const SEARCH_DEBOUNCE_MS = 300;

/** Keeps the query (and the request) one step behind the keystrokes. */
function useDebounced<T>(value: T, ms: number): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), ms);
    return () => clearTimeout(timer);
  }, [value, ms]);
  return debounced;
}

export interface ListControls {
  page: number;
  size: number;
  search: string;
  sort: string;
  order: SortOrder;
  filters: Record<string, string>;
  /** Ready to hand to usePagedList; the search term in it is debounced. */
  query: ListQuery;
  /** True when a search term or filter is narrowing the list. */
  isFiltered: boolean;
  setPage: (page: number) => void;
  setSize: (size: number) => void;
  setSearch: (search: string) => void;
  setFilter: (key: string, value: string) => void;
  toggleSort: (field: string) => void;
  reset: () => void;
}

/**
 * Holds the listing state (page, size, search, sort, filters) for one view.
 * Anything that changes which rows match resets the page, so the user never
 * lands on a page that no longer exists.
 */
export function useListControls(defaults?: {
  size?: number;
  sort?: string;
  order?: SortOrder;
  filters?: Record<string, string>;
}): ListControls {
  // Captured once: `reset` has to go back to the view's own starting point.
  const [initial] = useState(() => ({
    page: 1,
    size: defaults?.size ?? 20,
    search: "",
    // No sort field means the API's own default order (newest first).
    sort: defaults?.sort ?? "",
    order: defaults?.order ?? ("asc" as SortOrder),
    filters: defaults?.filters ?? {},
  }));
  const [state, setState] = useState(initial);
  const debouncedSearch = useDebounced(state.search, SEARCH_DEBOUNCE_MS);

  const query = useMemo<ListQuery>(
    () => ({
      page: state.page,
      size: state.size,
      search: debouncedSearch,
      sort: state.sort,
      order: state.order,
      filters: state.filters,
    }),
    [state.page, state.size, state.sort, state.order, state.filters, debouncedSearch],
  );

  const isFiltered =
    state.search.trim() !== "" || Object.values(state.filters).some((value) => value !== "");

  return {
    ...state,
    query,
    isFiltered,
    setPage: (page) => setState((s) => ({ ...s, page })),
    setSize: (size) => setState((s) => ({ ...s, size, page: 1 })),
    setSearch: (search) => setState((s) => ({ ...s, search, page: 1 })),
    setFilter: (key, value) =>
      setState((s) => ({ ...s, filters: { ...s.filters, [key]: value }, page: 1 })),
    toggleSort: (field) =>
      setState((s) => ({
        ...s,
        page: 1,
        sort: field,
        order: s.sort === field && s.order === "asc" ? "desc" : "asc",
      })),
    reset: () => setState(initial),
  };
}

export function ListToolbar({
  controls,
  placeholder = "Search…",
  children,
}: {
  controls: ListControls;
  placeholder?: string;
  children?: React.ReactNode;
}) {
  return (
    <div className="mb-3 flex flex-wrap items-center gap-2">
      <Input
        value={controls.search}
        onChange={(e) => controls.setSearch(e.target.value)}
        placeholder={placeholder}
        aria-label={placeholder}
        className="w-auto min-w-56 flex-1"
      />
      {children}
      {controls.isFiltered && (
        <Button variant="ghost" size="sm" onClick={controls.reset}>
          Clear
        </Button>
      )}
    </div>
  );
}

/** A filter dropdown for the toolbar. The empty value means "no filter". */
export function FilterSelect({
  label,
  value,
  onChange,
  children,
  className,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <Select
      aria-label={label}
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className={cn("w-auto min-w-36", value !== "" && "border-accent/50 text-fg", className)}
    >
      {children}
    </Select>
  );
}

/** A table header that sorts by `field`. Only pass fields the API accepts. */
export function SortHeader({
  controls,
  field,
  children,
  className,
}: {
  controls: ListControls;
  field: string;
  children: React.ReactNode;
  className?: string;
}) {
  const active = controls.sort === field;
  const Icon = !active ? ArrowDownUp : controls.order === "asc" ? ArrowUp : ArrowDown;
  return (
    <TH className={cn("p-0", className)}>
      <button
        type="button"
        onClick={() => controls.toggleSort(field)}
        className={cn(
          "flex w-full items-center gap-1.5 px-4 py-2.5 uppercase tracking-wider transition-colors hover:text-fg",
          active && "text-fg",
        )}
      >
        {children}
        <Icon className={cn("h-3 w-3", !active && "opacity-40")} />
      </button>
    </TH>
  );
}

export function Pagination({ controls, total }: { controls: ListControls; total: number }) {
  const pages = Math.max(1, Math.ceil(total / controls.size));
  const { page: current, setPage } = controls;

  // Deleting the last rows of the last page leaves the cursor past the end, and
  // the API answers such a page with no items at all. Step back instead of
  // showing an empty table.
  useEffect(() => {
    if (current > pages) setPage(pages);
  }, [current, pages, setPage]);

  const page = Math.min(current, pages);
  const from = total === 0 ? 0 : (page - 1) * controls.size + 1;
  const to = Math.min(total, page * controls.size);

  if (pages <= 1) return null;

  return (
    <div className="mt-3 flex flex-wrap items-center justify-between gap-3">
      <p className="text-[12px] text-muted">
        {from}–{to} of {total}
      </p>
      <div className="flex items-center gap-2">
        <Select
          aria-label="Rows per page"
          value={String(controls.size)}
          onChange={(e) => controls.setSize(Number(e.target.value))}
          className="h-8 w-auto text-[13px]"
        >
          {PAGE_SIZES.map((size) => (
            <option key={size} value={size}>
              {size} / page
            </option>
          ))}
        </Select>
        <Button
          variant="ghost"
          size="icon"
          className="h-8 w-8"
          disabled={page <= 1}
          onClick={() => controls.setPage(page - 1)}
          aria-label="Previous page"
        >
          <ChevronLeft className="h-4 w-4" />
        </Button>
        <span className="text-[12px] text-muted tabular-nums">
          {page} / {pages}
        </span>
        <Button
          variant="ghost"
          size="icon"
          className="h-8 w-8"
          disabled={page >= pages}
          onClick={() => controls.setPage(page + 1)}
          aria-label="Next page"
        >
          <ChevronRight className="h-4 w-4" />
        </Button>
      </div>
    </div>
  );
}

/**
 * Shown when the resource has rows but none on this page match — either the
 * filters exclude everything or a deletion shrank the list under the cursor.
 */
export function NoMatches({ controls, label }: { controls: ListControls; label: string }) {
  return (
    <EmptyState
      icon={<SearchX className="h-5 w-5" />}
      title={`No ${label} match`}
      description="Nothing here for the current search and filters."
      action={
        <Button variant="ghost" onClick={controls.reset}>
          Clear filters
        </Button>
      }
    />
  );
}

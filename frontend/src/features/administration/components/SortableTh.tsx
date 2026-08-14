/* eslint-disable react-refresh/only-export-components */
import { ChevronDown, ChevronUp, ChevronsUpDown } from "lucide-react";
import { useMemo, useState, type ReactNode } from "react";

import { Th } from "./ui/primitives";
import { cn } from "../lib/utils";

export type SortDirection = "asc" | "desc";

export function useSortState<K extends string>(initial: K) {
  const [sortKey, setSortKey] = useState<K>(initial);
  const [direction, setDirection] = useState<SortDirection>("asc");

  function toggleSort(field: K) {
    if (field === sortKey) {
      setDirection((current) => (current === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(field);
      setDirection("asc");
    }
  }

  return { sortKey, direction, toggleSort };
}

/**
 * Sorts on a field, with nulls held at the end regardless of direction.
 *
 * "Never signed in" is an absence rather than an extreme, so it should not
 * jump to the top when the direction flips — an operator sorting by last
 * activity is looking at people who *have* been active.
 */
export function useSort<T, K extends keyof T & string>(rows: T[], key: K, direction: SortDirection) {
  return useMemo(() => {
    const factor = direction === "asc" ? 1 : -1;
    return [...rows].sort((a, b) => {
      const left = a[key];
      const right = b[key];

      if (left === null || left === undefined) return right === null || right === undefined ? 0 : 1;
      if (right === null || right === undefined) return -1;

      if (typeof left === "number" && typeof right === "number") return (left - right) * factor;
      return String(left).localeCompare(String(right), undefined, { sensitivity: "base" }) * factor;
    });
  }, [rows, key, direction]);
}

export function SortableTh<K extends string>({
  field,
  sortKey,
  direction,
  onSort,
  children,
  className,
}: {
  field: K;
  sortKey: K;
  direction: SortDirection;
  onSort: (field: K) => void;
  children: ReactNode;
  className?: string;
}) {
  const active = field === sortKey;
  const Icon = active ? (direction === "asc" ? ChevronUp : ChevronDown) : ChevronsUpDown;

  return (
    <Th className={cn("p-0", className)} aria-sort={active ? (direction === "asc" ? "ascending" : "descending") : "none"}>
      <button
        type="button"
        onClick={() => onSort(field)}
        className={cn(
          "flex w-full items-center gap-1.5 px-5 py-2.5 text-left transition-colors hover:text-cream-bright",
          active && "text-cream-primary",
        )}
      >
        {children}
        <Icon className={cn("size-3", active ? "opacity-90" : "opacity-40")} strokeWidth={2} aria-hidden="true" />
      </button>
    </Th>
  );
}

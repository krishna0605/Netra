import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/** "10 Aug 2026, 14:22" — the format every timestamp column uses. */
export function dateTimeLabel(value: string) {
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) return "Not recorded";
  return date.toLocaleString("en-IN", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });
}

/** "14:41:08" — for dense log tables where the date is already in the filter. */
export function timeLabel(value: string) {
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) return "—";
  return date.toLocaleTimeString("en-IN", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

/** "2 min ago" / "3 d ago" — relative ages read faster than absolute ones in
 *  a scan column, but never use them where an exact time is evidence. */
export function relativeLabel(value: string) {
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) return "Never";
  const seconds = Math.round((Date.now() - date.valueOf()) / 1000);
  if (seconds < 60) return "just now";
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours} h ago`;
  const days = Math.round(hours / 24);
  if (days < 30) return `${days} d ago`;
  return dateTimeLabel(value);
}

export function initials(name: string) {
  return name
    .replace(/[^A-Za-z .]/g, "")
    .split(/[\s.]+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase() ?? "")
    .join("");
}

import type { LogEvent } from "./analyzer";

export type ActivityFilter = "all" | "probes" | "login" | "post" | "uploads-php";

export interface InvestigationFilters {
  search: string;
  kind: string;
  status: string;
  exactStatus: string;
  ip: string;
  path: string;
  userAgent: string;
  activity: ActivityFilter;
  fromTime: string;
  toTime: string;
}

export function isExploitProbe(event: LogEvent): boolean {
  if (event.kind !== "access") return false;
  const path = event.path || "";
  let decoded = path;
  try { decoded = decodeURIComponent(path); } catch { /* use the recorded path */ }
  return /wp-config\.php|\.env(?:$|\/)|\.git\/|\/vendor\/phpunit|\/cgi-bin\/|\/etc\/passwd|\.\.\/|\/wp-content\/uploads\/.*\.php$|\/shell\.php$|\/eval-stdin\.php$/i.test(decoded)
    || /(?:union(?:\s|\+|%20)+select|<script|%3cscript)/i.test(event.raw);
}

export function matchesInvestigation(event: LogEvent, filters: InvestigationFilters): boolean {
  const query = filters.search.trim().toLowerCase();
  if (filters.kind !== "all" && event.kind !== filters.kind) return false;
  if (filters.ip.trim() && event.ip?.toLowerCase() !== filters.ip.trim().toLowerCase()) return false;
  if (filters.path && event.path !== filters.path) return false;
  if (filters.userAgent && !event.userAgent?.startsWith(filters.userAgent)) return false;
  if (filters.status !== "all" && (event.status === undefined || `${Math.floor(event.status / 100)}xx` !== filters.status)) return false;
  if (filters.exactStatus.trim() && String(event.status ?? "") !== filters.exactStatus.trim()) return false;
  if (query && ![event.raw, event.ip, event.path, event.component, event.source, event.userAgent].some(value => value?.toLowerCase().includes(query))) return false;
  if (filters.fromTime && (!event.timestamp || Date.parse(event.timestamp) < Date.parse(filters.fromTime))) return false;
  if (filters.toTime && (!event.timestamp || Date.parse(event.timestamp) >= Date.parse(filters.toTime) + 60_000)) return false;
  switch (filters.activity) {
    case "probes": return isExploitProbe(event);
    case "login": return event.kind === "access" && /(?:^|\/)(?:wp-login\.php|xmlrpc\.php)(?:$|\/)/i.test(event.path || "");
    case "post": return event.kind === "access" && event.method === "POST";
    case "uploads-php": return event.kind === "access" && /\/wp-content\/uploads\/.*\.php$/i.test(event.path || "");
    default: return true;
  }
}

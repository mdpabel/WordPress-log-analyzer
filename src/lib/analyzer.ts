export type LogKind = "access" | "error";
import { isExploitProbe } from "./investigation";
export type Severity = "critical" | "high" | "medium" | "info";
export type FindingCategory = "security" | "errors" | "access" | "performance";

export interface LogEvent {
  id: number;
  source: string;
  line: number;
  kind: LogKind;
  timestamp: string | null;
  timestampRaw?: string;
  raw: string;
  ip?: string;
  method?: string;
  path?: string;
  status?: number;
  bytes?: number;
  referrer?: string;
  userAgent?: string;
  message?: string;
  stack?: string;
  level?: string;
  component?: string;
  durationMs?: number;
}

export interface Finding {
  id: string;
  category: FindingCategory;
  severity: Severity;
  title: string;
  summary: string;
  explanation: string;
  nextSteps: string[];
  count: number;
  eventIds: number[];
  confidence: "observed" | "likely" | "needs more evidence";
}

export interface Analysis {
  events: LogEvent[];
  findings: Finding[];
  totalLines: number;
  parsedCount: number;
  skippedLines: number;
  truncated: boolean;
  unparsedExamples: { source: string; line: number; raw: string }[];
  undatedCount: number;
  sources: string[];
  formats: Record<string, number>;
  startedAt: string | null;
  endedAt: string | null;
  accessCount: number;
  errorCount: number;
  statusCounts: Record<string, number>;
  uniqueIps: number;
  uniqueIpsApproximate: boolean;
  topCountsApproximate: boolean;
  traffic: { label: string; count: number; errors: number }[];
  topPaths: { label: string; count: number }[];
  topIps: { label: string; count: number }[];
  topUserAgents: { label: string; count: number }[];
  topStatusCodes: { label: string; count: number }[];
  userAgentsGroupedByPrefix: boolean;
}

const months: Record<string, number> = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };
const MAX_EVENTS = 120_000;
const TAIL_EVENTS = 20_000;
const MAX_DISTINCT_KEYS = 50_000;
const MAX_USER_AGENTS = 2_000;
const MAX_USER_AGENT_LENGTH = 256;
const MAX_EXACT_IPS = 100_000;

function addBoundedCount(counts: Map<string, number>, key: string, limit = MAX_DISTINCT_KEYS): boolean {
  const current = counts.get(key);
  if (current !== undefined) { counts.set(key, current + 1); return false; }
  if (counts.size < limit) { counts.set(key, 1); return false; }
  // Misra-Gries keeps frequent keys with bounded memory. Counts become lower bounds.
  for (const [label, count] of counts) {
    if (count === 1) counts.delete(label);
    else counts.set(label, count - 1);
  }
  return true;
}

function recordIp(registers: Uint8Array, ip: string): void {
  let hash = 2166136261;
  for (let i = 0; i < ip.length; i++) hash = Math.imul(hash ^ ip.charCodeAt(i), 16777619);
  hash >>>= 0;
  const index = hash >>> 22;
  const rank = Math.min(23, Math.clz32((hash << 10) >>> 0) + 1);
  registers[index] = Math.max(registers[index], rank);
}

function estimateIps(registers: Uint8Array): number {
  const size = registers.length;
  let sum = 0, empty = 0;
  for (const rank of registers) { sum += 2 ** -rank; if (!rank) empty++; }
  const estimate = (0.7213 / (1 + 1.079 / size)) * size * size / sum;
  return Math.round(estimate <= 2.5 * size && empty ? size * Math.log(size / empty) : estimate);
}

function redact(raw: string): string {
  return raw
    .replace(/([?&](?:token|key|api_key|apikey|password|pass|pwd|secret|nonce|auth|code|session|signature|access_token|refresh_token|email)=)[^&\s"']+/gi, "$1[REDACTED]")
    .replace(/((?:authorization|cookie|set-cookie)\s*[:=]\s*)[^\s"']+/gi, "$1[REDACTED]");
}

function apacheTime(input: string): string | null {
  const m = input.match(/^(\d{2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})$/);
  if (!m || months[m[2]] === undefined) return null;
  const offset = (Number(m[8]) * 60 + Number(m[9])) * (m[7] === "+" ? 1 : -1);
  const value = Date.UTC(Number(m[3]), months[m[2]], Number(m[1]), Number(m[4]), Number(m[5]), Number(m[6])) - offset * 60_000;
  return new Date(value).toISOString();
}

function errorTime(input: string, assumedOffsetMinutes: number | null): string | null {
  const php = input.match(/^(\d{1,2})-([A-Za-z]{3})-(\d{4}) (\d{2}):(\d{2}):(\d{2})(?: (UTC))?$/);
  if (php && months[php[2]] !== undefined && (php[7] || assumedOffsetMinutes !== null)) return new Date(Date.UTC(Number(php[3]), months[php[2]], Number(php[1]), Number(php[4]), Number(php[5]), Number(php[6])) - (php[7] ? 0 : assumedOffsetMinutes || 0) * 60_000).toISOString();
  const apache = input.match(/^[A-Za-z]{3} ([A-Za-z]{3})\s+(\d{1,2}) (\d{2}):(\d{2}):(\d{2})(?:\.\d+)? (\d{4})$/);
  if (apache && months[apache[1]] !== undefined && assumedOffsetMinutes !== null) return new Date(Date.UTC(Number(apache[6]), months[apache[1]], Number(apache[2]), Number(apache[3]), Number(apache[4]), Number(apache[5])) - assumedOffsetMinutes * 60_000).toISOString();
  const nginx = input.match(/^(\d{4})\/(\d{2})\/(\d{2}) (\d{2}):(\d{2}):(\d{2})$/);
  if (nginx && assumedOffsetMinutes !== null) return new Date(Date.UTC(Number(nginx[1]), Number(nginx[2]) - 1, Number(nginx[3]), Number(nginx[4]), Number(nginx[5]), Number(nginx[6])) - assumedOffsetMinutes * 60_000).toISOString();
  return null;
}

function componentFrom(message: string): string | undefined {
  const plugin = message.match(/wp-content[\\/]plugins[\\/]([^\\/\s:]+)/i);
  if (plugin) return `Plugin: ${plugin[1]}`;
  const theme = message.match(/wp-content[\\/]themes[\\/]([^\\/\s:]+)/i);
  if (theme) return `Theme: ${theme[1]}`;
  if (/wp-includes[\\/]|wp-admin[\\/]/i.test(message)) return "WordPress core";
  return undefined;
}

function cleanPath(request: string): { method?: string; path?: string } {
  const match = request.match(/^([A-Z]+)\s+(\S+)/);
  if (!match) return {};
  const rawPath = match[2];
  let path = rawPath;
  try { if (/^https?:\/\//i.test(rawPath)) path = new URL(rawPath).pathname; } catch { /* retain request target */ }
  return { method: match[1], path: path.split("?")[0] || "/" };
}

export function parseLine(rawLine: string, source: string, line: number, id: number, assumedOffsetMinutes: number | null = null): LogEvent | null {
  const raw = redact(rawLine.trim());
  if (!raw) return null;

  // Apache and NGINX common/combined formats, including a leading virtual host.
  const access = raw.match(/^(?:(\S+)\s+)?(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([^"]*)"\s+(\d{3})\s+(\S+)(?:\s+"([^"]*)"\s+"([^"]*)")?/);
  if (access) {
    const timestamp = apacheTime(access[3]);
    if (!timestamp) return null;
    const request = cleanPath(access[4]);
    return { id, source, line, kind: "access", timestamp, timestampRaw: access[3], raw, ip: access[2], method: request.method, path: request.path, status: Number(access[5]), bytes: access[6] === "-" ? undefined : Number(access[6]), referrer: access[7], userAgent: access[8] };
  }

  const php = raw.match(/^\[([^\]]+)\]\s*(.*)$/);
  if (php) {
    const timestamp = errorTime(php[1], assumedOffsetMinutes);
    if (timestamp || /^(?:\d{1,2}-[A-Za-z]{3}-\d{4}|[A-Za-z]{3} [A-Za-z]{3} \s*\d{1,2})/.test(php[1])) {
      const body = php[2];
      const level = /fatal error|uncaught|parse error/i.test(body) ? "fatal" : /warning/i.test(body) ? "warning" : /notice|deprecated/i.test(body) ? "notice" : "error";
      return { id, source, line, kind: "error", timestamp, timestampRaw: php[1], raw, message: body, level, component: componentFrom(body), ip: body.match(/\[client ([^\]]+)\]/)?.[1] };
    }
  }

  const nginx = raw.match(/^(\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}) \[([^\]]+)\] (.*)$/);
  if (nginx) {
    const body = nginx[3];
    return { id, source, line, kind: "error", timestamp: errorTime(nginx[1], assumedOffsetMinutes), timestampRaw: nginx[1], raw, message: body, level: nginx[2].toLowerCase(), component: componentFrom(body), ip: body.match(/client: ([^,]+)/)?.[1] };
  }

  return null;
}

function addFinding(out: Finding[], finding: Finding): void { if (finding.count) out.push(finding); }
function ids(events: LogEvent[], limit = 200): number[] { return events.slice(0, limit).map(e => e.id); }
function plural(count: number, singular: string, pluralForm = `${singular}s`): string { return `${count} ${count === 1 ? singular : pluralForm}`; }
function excerpt(value: string, max = 190): string { if (value.length <= max) return value; const cut = value.slice(0, max); return `${cut.slice(0, cut.lastIndexOf(" ") > max / 2 ? cut.lastIndexOf(" ") : max).trim()}…`; }
function busiestWindow(events: LogEvent[], durationMs: number): LogEvent[] {
  const sorted = events.filter(e => e.timestamp).sort((a, b) => (a.timestamp || "").localeCompare(b.timestamp || ""));
  let start = 0, bestStart = 0, bestEnd = 0;
  for (let end = 0; end < sorted.length; end++) {
    const endTime = Date.parse(sorted[end].timestamp!);
    while (start < end && endTime - Date.parse(sorted[start].timestamp!) > durationMs) start++;
    if (end - start + 1 > bestEnd - bestStart) { bestStart = start; bestEnd = end + 1; }
  }
  return sorted.slice(bestStart, bestEnd);
}

function diagnose(message: string): { explanation: string; steps: string[] } {
  if (/allowed memory size|out of memory/i.test(message)) return { explanation: "PHP reached its memory limit. The stack trace and nearby requests can help identify what consumed it; the limit alone does not identify the cause.", steps: ["Inspect the referenced script and repeated request paths.", "Check recent plugin/theme changes and PHP memory usage.", "Review the hosting limit; raise it only after checking for a leak or unusually costly request."] };
  if (/call to a member function .* on (?:null|false)/i.test(message)) return { explanation: "PHP tried to call a method on a value that was null or false. The theme or plugin expected an object that was unavailable in this request; the log does not show why it was missing.", steps: ["Inspect the first application file and line in the fatal error and its stack trace.", "Check the request context and the value returned before the method call on a staging copy.", "Update the affected theme or plugin if a fix exists; otherwise guard the missing value in the code and retest."] };
  if (/undefined function|class .* not found/i.test(message)) return { explanation: "Code called a function or class that was unavailable. A missing dependency, partial update, or version mismatch may be involved.", steps: ["Check the first application file and line in the error.", "Verify plugin/theme files and versions, then reproduce on staging.", "Review recent deployments and PHP compatibility."] };
  if (/database|mysqli|pdo|sqlstate|too many connections/i.test(message)) return { explanation: "The application reported a database problem. The exact message determines whether it is a connection, query, or resource issue.", steps: ["Read the full database message and its timestamp.", "Check database service health, connection limits, and relevant configuration.", "Compare the error window with 5xx requests."] };
  if (/timed out|timeout|upstream/i.test(message)) return { explanation: "A request or upstream process did not respond in time. Load, a slow query, or a blocked dependency may be involved.", steps: ["Compare affected URLs with access-log timing and traffic volume.", "Review PHP-FPM, web-server, and database logs in the same window.", "Inspect long-running requests before increasing timeouts."] };
  if (/permission denied|no space left|disk full|quota/i.test(message)) return { explanation: "The server could not access or write a required resource.", steps: ["Check the affected file or directory named in the error.", "Inspect ownership, permissions, available disk space, and account quota."] };
  return { explanation: "The log records an application or server failure. The message and stack trace are the best starting evidence.", steps: ["Inspect the cited file, line, and stack trace.", "Compare the timestamp with failed requests and recent changes.", "Reproduce safely on staging if the cause remains unclear."] };
}

function makeFindings(events: LogEvent[]): Finding[] {
  const out: Finding[] = [];
  const accesses = events.filter(e => e.kind === "access");
  const errors = events.filter(e => e.kind === "error");
  const failures = accesses.filter(e => (e.status || 0) >= 500);
  const failureTimes = failures.map(e => e.timestamp ? Date.parse(e.timestamp) : NaN).filter(Number.isFinite).sort((a, b) => a - b);
  const overlappingErrors = errors.filter(e => {
    if (!e.timestamp || !failureTimes.length) return false;
    const time = Date.parse(e.timestamp);
    let low = 0, high = failureTimes.length;
    while (low < high) { const middle = (low + high) >>> 1; if (failureTimes[middle] < time) low = middle + 1; else high = middle; }
    return (low < failureTimes.length && Math.abs(failureTimes[low] - time) <= 60_000) || (low > 0 && Math.abs(failureTimes[low - 1] - time) <= 60_000);
  });
  addFinding(out, { id: "http-5xx", category: "errors", severity: failures.length >= 10 ? "critical" : "high", title: "Server errors in access traffic", summary: `${plural(failures.length, "request")} returned 5xx responses across ${plural(new Set(failures.map(e => e.path)).size, "path")}.${overlappingErrors.length ? ` ${plural(overlappingErrors.length, "error-log entry", "error-log entries")} occurred within one minute.` : ""}`, explanation: overlappingErrors.length ? "Error entries occurred near failed requests. Their timing makes them useful leads, but without a shared request ID they are not a confirmed one-to-one match." : "The server failed these requests. An access log shows scope and timing; a matching error log is needed to explain the cause.", nextSteps: ["Inspect the affected paths and first failure time.", overlappingErrors.length ? "Compare nearby error messages and their stack traces." : "Upload the matching PHP, WordPress, or web-server error log.", "Compare traffic volume and recent site changes around the start time."], count: failures.length, eventIds: ids([...failures, ...overlappingErrors]), confidence: "observed" });

  const fatalGroups = new Map<string, LogEvent[]>();
  for (const e of errors.filter(e => e.level === "fatal")) {
    const key = (e.message || "Fatal error").replace(/ on line \d+/gi, " on line #").replace(/:\d+/g, ":#").slice(0, 1000);
    if (!fatalGroups.has(key)) fatalGroups.set(key, []);
    fatalGroups.get(key)!.push(e);
  }
  for (const [key, group] of [...fatalGroups].sort((a, b) => b[1].length - a[1].length).slice(0, 8)) {
    const lead = group[0]; const advice = diagnose(lead.message || key);
    addFinding(out, { id: `fatal-${out.length}`, category: "errors", severity: "critical", title: lead.component ? `Fatal error in ${lead.component}` : "PHP fatal error", summary: `${plural(group.length, "occurrence")}. ${excerpt(lead.message || key)}`, explanation: advice.explanation, nextSteps: advice.steps, count: group.length, eventIds: ids(group), confidence: "observed" });
  }

  const auth = accesses.filter(e => /(?:^|\/)(?:wp-login\.php|xmlrpc\.php)(?:$|\/)/i.test(e.path || ""));
  const authByIp = new Map<string, LogEvent[]>();
  for (const e of auth) { const ip = e.ip || "unknown"; if (!authByIp.has(ip)) authByIp.set(ip, []); authByIp.get(ip)!.push(e); }
  const distributedAuthBurst = busiestWindow(auth, 10 * 60_000);
  const singleIpAuthBurst = [...authByIp.values()].map(group => busiestWindow(group, 10 * 60_000)).sort((a, b) => b.length - a.length)[0] || [];
  const authBurst = distributedAuthBurst.length >= 8 ? distributedAuthBurst : singleIpAuthBurst;
  if (distributedAuthBurst.length >= 8 || singleIpAuthBurst.length >= 5) addFinding(out, { id: "auth-pressure", category: "security", severity: authBurst.length >= 30 ? "high" : "medium", title: "Login and XML-RPC pressure", summary: `${plural(authBurst.length, "request")} targeted WordPress login or XML-RPC within 10 minutes from ${plural(new Set(authBurst.map(e => e.ip)).size, "recorded IP")}.`, explanation: "Repeated requests can indicate password guessing or automation. HTTP responses alone do not confirm whether a login succeeded.", nextSteps: ["Inspect rate, source IPs, and paths in the evidence view.", "Check WordPress or security-plugin authentication events for outcomes.", "Review rate limits and XML-RPC usage before changing access rules."], count: authBurst.length, eventIds: ids(authBurst), confidence: "likely" });

  const suspicious = accesses.filter(isExploitProbe);
  addFinding(out, { id: "exploit-probes", category: "security", severity: suspicious.length >= 10 ? "high" : "medium", title: "Sensitive-file and exploit probes", summary: `${plural(suspicious.length, "request")} ${suspicious.length === 1 ? "matches" : "match"} sensitive paths or common exploit patterns.`, explanation: "These requests are suspicious probes. A matching URL or successful HTTP response is not proof that code ran or data was exposed.", nextSteps: ["Review the targeted paths, source IPs, and response codes.", "Check WAF events and server files for any unusual follow-on activity.", "Confirm sensitive files are inaccessible and update affected software if relevant."], count: suspicious.length, eventIds: ids(suspicious), confidence: "likely" });

  const byIp = new Map<string, LogEvent[]>();
  for (const e of accesses) { const ip = e.ip || "unknown"; if (!byIp.has(ip)) byIp.set(ip, []); byIp.get(ip)!.push(e); }
  const scanners = [...byIp].map(([, group]) => busiestWindow(group.filter(e => e.status === 404), 10 * 60_000)).filter(group => group.length >= 8 && new Set(group.map(e => e.path)).size >= 8).flat();
  if (scanners.length) addFinding(out, { id: "path-scans", category: "security", severity: "medium", title: "Broad path scanning", summary: `${plural(scanners.length, "request")} came from IPs with many distinct 404 paths within 10 minutes.`, explanation: "Rapid requests for many missing paths often indicate reconnaissance. Some crawlers can look similar.", nextSteps: ["Review the exact paths and request timing.", "Compare with known crawlers and WAF/security events.", "Apply rate limiting only after checking for legitimate traffic."], count: scanners.length, eventIds: ids(scanners), confidence: "likely" });

  const busy = [...byIp].map(([, group]) => busiestWindow(group, 5 * 60_000)).filter(group => group.length >= 100).flat();
  if (busy.length) addFinding(out, { id: "heavy-traffic", category: "performance", severity: "medium", title: "High-volume source IPs", summary: `${busy.length} requests came from source-IP bursts of at least 100 requests within five minutes.`, explanation: "High volume can be a crawler, monitoring, a shared proxy, or abusive traffic. The log alone does not determine intent.", nextSteps: ["Inspect request rate and targeted paths for each IP.", "Check CDN/proxy configuration before treating an IP as a visitor.", "Compare peaks with error and latency trends."], count: busy.length, eventIds: ids(busy), confidence: "observed" });

  const missing = accesses.filter(e => e.status === 404);
  if (missing.length >= 3) addFinding(out, { id: "404s", category: "access", severity: "info", title: "Repeated missing paths", summary: `${plural(missing.length, "request")} returned 404 across ${plural(new Set(missing.map(e => e.path)).size, "path")}.`, explanation: "Repeated 404s may be broken links, removed content, or scans. Review the paths and referrers to distinguish them.", nextSteps: ["Sort 404 paths by frequency and referrer.", "Fix internal links or add redirects for legitimate removed pages.", "Investigate random-looking probes in the Security view."], count: missing.length, eventIds: ids(missing), confidence: "observed" });
  return out.sort((a, b) => ({ critical: 0, high: 1, medium: 2, info: 3 })[a.severity] - ({ critical: 0, high: 1, medium: 2, info: 3 })[b.severity]);
}

export class AnalysisBuilder {
  private events: LogEvent[] = [];
  private tail: LogEvent[] = [];
  private tailIndex = 0;
  private parsedCount = 0;
  private totalLines = 0;
  private skippedLines = 0;
  private truncated = false;
  private sources = new Set<string>();
  private unparsedExamples: { source: string; line: number; raw: string }[] = [];
  private accessCount = 0;
  private errorCount = 0;
  private undatedCount = 0;
  private statusCounts: Record<string, number> = {};
  private firstTimestamp: string | null = null;
  private lastTimestamp: string | null = null;
  private traffic = new Map<string, { count: number; errors: number }>();
  private pathCounts = new Map<string, number>();
  private ipCounts = new Map<string, number>();
  private userAgentCounts = new Map<string, number>();
  private exactStatusCounts = new Map<string, number>();
  private userAgentsGroupedByPrefix = false;
  private uniqueIps = new Set<string>();
  private ipRegisters = new Uint8Array(1024);
  private uniqueIpsApproximate = false;
  private topCountsApproximate = false;
  private lastEvent: LogEvent | null = null;

  constructor(private assumedOffsetMinutes: number | null = null) {}

  add(line: string, source: string, lineNumber: number): void {
    this.totalLines++;
    this.sources.add(source);
    if (!line.trim()) return;
    if (/^\s*(?:Stack trace:|#\d+\s|thrown in\s)/i.test(line)) {
      const previous = this.lastEvent;
      if (previous?.kind === "error" && previous.source === source) {
        const safe = redact(line.slice(0, 4000));
        previous.stack = `${previous.stack || ""}${previous.stack ? "\n" : ""}${safe}`;
        previous.raw += `\n${safe}`;
        if (!previous.component) previous.component = componentFrom(safe);
        return;
      }
    }
    const event = parseLine(line, source, lineNumber, this.parsedCount + 1, this.assumedOffsetMinutes);
    if (!event) {
      this.lastEvent = null;
      this.skippedLines++;
      if (this.unparsedExamples.length < 5) this.unparsedExamples.push({ source, line: lineNumber, raw: redact(line.slice(0, 500)) });
      return;
    }
    this.parsedCount++;
    this.lastEvent = event;
    if (event.kind === "access") {
      this.accessCount++;
      const status = `${Math.floor((event.status || 0) / 100)}xx`;
      this.statusCounts[status] = (this.statusCounts[status] || 0) + 1;
      const exactStatus = String(event.status || 0);
      this.exactStatusCounts.set(exactStatus, (this.exactStatusCounts.get(exactStatus) || 0) + 1);
      const path = event.path || "unknown";
      const ip = event.ip || "unknown";
      this.topCountsApproximate = addBoundedCount(this.pathCounts, path) || this.topCountsApproximate;
      this.topCountsApproximate = addBoundedCount(this.ipCounts, ip) || this.topCountsApproximate;
      const userAgent = event.userAgent?.trim();
      if (userAgent && userAgent !== "-") {
        if (userAgent.length > MAX_USER_AGENT_LENGTH) this.userAgentsGroupedByPrefix = true;
        this.topCountsApproximate = addBoundedCount(this.userAgentCounts, userAgent.slice(0, MAX_USER_AGENT_LENGTH), MAX_USER_AGENTS) || this.topCountsApproximate;
      }
      if (event.ip) {
        recordIp(this.ipRegisters, event.ip);
        if (!this.uniqueIpsApproximate) {
          this.uniqueIps.add(event.ip);
          if (this.uniqueIps.size > MAX_EXACT_IPS) { this.uniqueIpsApproximate = true; this.uniqueIps.clear(); }
        }
      }
    } else this.errorCount++;
    if (event.timestamp) {
      if (!this.firstTimestamp || event.timestamp < this.firstTimestamp) this.firstTimestamp = event.timestamp;
      if (!this.lastTimestamp || event.timestamp > this.lastTimestamp) this.lastTimestamp = event.timestamp;
      const minute = Math.floor(Number(event.timestamp.slice(14, 16)) / 5) * 5;
      const key = event.timestamp.slice(0, 14) + String(minute).padStart(2, "0");
      const point = this.traffic.get(key) || { count: 0, errors: 0 };
      point.count++;
      if (event.kind === "error" || (event.status || 0) >= 500) point.errors++;
      this.traffic.set(key, point);
    } else this.undatedCount++;
    if (this.events.length < MAX_EVENTS - TAIL_EVENTS) this.events.push(event);
    else if (this.tail.length < TAIL_EVENTS) this.tail.push(event);
    else {
      this.truncated = true;
      this.tail[this.tailIndex] = event;
      this.tailIndex = (this.tailIndex + 1) % TAIL_EVENTS;
    }
  }

  finish(): Analysis {
    const tail = this.truncated ? [...this.tail.slice(this.tailIndex), ...this.tail.slice(0, this.tailIndex)] : this.tail;
    const events = [...this.events, ...tail].sort((a, b) => (a.timestamp || "9999").localeCompare(b.timestamp || "9999"));
    const top = (counts: Map<string, number>) => [...counts].map(([label, count]) => ({ label, count })).sort((a, b) => b.count - a.count || a.label.localeCompare(b.label)).slice(0, 8);
    return { events, findings: makeFindings(events), totalLines: this.totalLines, parsedCount: this.parsedCount, skippedLines: this.skippedLines, truncated: this.truncated, unparsedExamples: this.unparsedExamples, undatedCount: this.undatedCount, sources: [...this.sources], formats: { access: this.accessCount, error: this.errorCount }, startedAt: this.firstTimestamp, endedAt: this.lastTimestamp, accessCount: this.accessCount, errorCount: this.errorCount, statusCounts: this.statusCounts, uniqueIps: this.uniqueIpsApproximate ? Math.max(MAX_EXACT_IPS, estimateIps(this.ipRegisters)) : this.uniqueIps.size, uniqueIpsApproximate: this.uniqueIpsApproximate, topCountsApproximate: this.topCountsApproximate, userAgentsGroupedByPrefix: this.userAgentsGroupedByPrefix, traffic: [...this.traffic].sort(([a], [b]) => a.localeCompare(b)).map(([label, v]) => ({ label, ...v })).slice(-48), topPaths: top(this.pathCounts), topIps: top(this.ipCounts), topUserAgents: top(this.userAgentCounts), topStatusCodes: top(this.exactStatusCounts) };
  }
}

export function analyzeText(text: string, source = "pasted log"): Analysis {
  const builder = new AnalysisBuilder();
  text.split(/\r?\n/).forEach((line, index) => builder.add(line, source, index + 1));
  return builder.finish();
}

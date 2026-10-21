import test from "node:test";
import assert from "node:assert/strict";
import { analyzeText, parseLine } from "../src/lib/analyzer";
import { demoLog } from "../src/lib/demo";
import { buildResponse } from "../src/lib/report";
import { ingestBrowserFile } from "../src/lib/import";
import { gzipSync } from "node:zlib";
import { readFile } from "node:fs/promises";
import { AnalysisBuilder } from "../src/lib/analyzer";
import { matchesInvestigation, type InvestigationFilters } from "../src/lib/investigation";

test("parses Apache combined access and WordPress fatal logs", () => {
  const result = analyzeText(demoLog);
  assert.equal(result.accessCount, 17);
  assert.equal(result.errorCount, 3);
  assert.equal(result.statusCounts["5xx"], 3);
  assert.deepEqual(result.topUserAgents[0], { label: "python-requests/2.31", count: 8 });
  assert.deepEqual(result.topStatusCodes[0], { label: "200", count: 10 });
  assert.deepEqual(result.topIps[0], { label: "198.51.100.17", count: 8 });
  assert.ok(result.findings.some(f => f.id === "auth-pressure"));
  assert.ok(result.findings.some(f => f.id === "exploit-probes"));
  assert.ok(result.findings.some(f => f.id.startsWith("fatal-")));
  assert.equal(result.skippedLines, 0);
});

test("parses virtual-host access and NGINX error formats", () => {
  const access = parseLine('example.com 203.0.113.5 - - [21/Oct/2026:10:24:36 +0600] "GET /shop/?a=1 HTTP/1.1" 200 1024 "-" "Mozilla/5.0"', "access", 1, 1);
  assert.equal(access?.kind, "access");
  assert.equal(access?.ip, "203.0.113.5");
  assert.equal(access?.path, "/shop/");
  assert.equal(access?.timestamp, "2026-10-21T04:24:36.000Z");
  const error = parseLine('2026/10/21 10:24:36 [error] 42#42: *7 upstream timed out, client: 203.0.113.5, server: example.com', "error", 1, 2);
  assert.equal(error?.kind, "error");
  assert.equal(error?.level, "error");
});

test("redacts common secrets from displayed raw lines", () => {
  const event = parseLine('203.0.113.5 - - [21/Oct/2026:10:24:36 +0000] "GET /reset?token=very-secret&foo=1 HTTP/1.1" 200 10 "-" "Test"', "access", 1, 1);
  assert.ok(event);
  assert.ok(!event.raw.includes("very-secret"));
  assert.ok(event.raw.includes("token=[REDACTED]"));
});

test("keeps timezone-less errors undated until an offset is supplied", () => {
  const line = '2026/10/21 10:24:36 [error] 42#42: *7 upstream timed out, client: 203.0.113.5';
  const unknown = analyzeText(line);
  assert.equal(unknown.errorCount, 1);
  assert.equal(unknown.undatedCount, 1);
  assert.equal(unknown.startedAt, null);
  const specified = parseLine(line, "nginx", 1, 1, 360);
  assert.equal(specified?.timestamp, "2026-10-21T04:24:36.000Z");
});

test("shows unrecognized input instead of silently discarding it", () => {
  const result = analyzeText("not a log line");
  assert.equal(result.skippedLines, 1);
  assert.equal(result.unparsedExamples[0].line, 1);
});

test("returns a readable evidence-based response", () => {
  const response = buildResponse(analyzeText(demoLog));
  assert.match(response.text, /Login and XML-RPC pressure/);
  assert.match(response.text, /Allowed memory size|Fatal error/);
  assert.match(response.text, /Next checks:/);
  assert.match(response.text, /Access overview/);
  assert.match(response.text, /do not confirm successful logins/);
});

test("keeps PHP stack traces attached to their fatal event", () => {
  const result = analyzeText("[21-Oct-2026 09:15:14 UTC] PHP Fatal error: Uncaught TypeError in /home/site/wp-includes/a.php on line 20\nStack trace:\n#0 /home/site/wp-content/plugins/shop/pay.php(4): pay()\n  thrown in /home/site/wp-includes/a.php on line 20");
  assert.equal(result.errorCount, 1);
  assert.equal(result.skippedLines, 0);
  assert.match(result.events[0].stack || "", /plugins\/shop/);
});

test("does not call sparse login requests a burst", () => {
  const lines = Array.from({ length: 8 }, (_, hour) => `203.0.113.5 - - [21/Oct/2026:${String(hour).padStart(2, "0")}:00:00 +0000] "POST /wp-login.php HTTP/1.1" 200 100 "-" "Mozilla/5.0"`);
  const result = analyzeText(lines.join("\n"));
  assert.ok(!result.findings.some(f => f.id === "auth-pressure"));
});

test("traces suspicious requests alongside later activity from the same IP", () => {
  const lines = [
    '203.0.113.5 - - [21/Oct/2026:10:00:00 +0000] "GET /.env HTTP/1.1" 404 100 "-" "Scanner"',
    '203.0.113.5 - - [21/Oct/2026:10:02:00 +0000] "POST /wp-admin/update.php HTTP/1.1" 200 100 "-" "Scanner"',
    '203.0.113.5 - - [21/Oct/2026:10:03:00 +0000] "GET /wp-content/uploads/shell.php HTTP/1.1" 200 100 "-" "Scanner"',
    '198.51.100.2 - - [21/Oct/2026:10:03:00 +0000] "GET / HTTP/1.1" 200 100 "-" "Browser"',
  ];
  const result = analyzeText(lines.join("\n"));
  const filters: InvestigationFilters = { search: "", kind: "all", status: "all", exactStatus: "", ip: "203.0.113.5", path: "", userAgent: "", activity: "all", fromTime: "", toTime: "" };
  assert.equal(result.events.filter(event => matchesInvestigation(event, filters)).length, 3);
  assert.equal(result.events.filter(event => matchesInvestigation(event, { ...filters, activity: "probes" })).length, 2);
  assert.equal(result.events.filter(event => matchesInvestigation(event, { ...filters, activity: "post" })).length, 1);
  assert.equal(result.events.filter(event => matchesInvestigation(event, { ...filters, activity: "uploads-php", exactStatus: "200" })).length, 1);
  assert.equal(result.events.filter(event => matchesInvestigation(event, { ...filters, path: "/wp-admin/update.php", userAgent: "Scan" })).length, 1);
  assert.equal(result.events.filter(event => matchesInvestigation(event, { ...filters, fromTime: "2026-10-21T10:02:00Z", toTime: "2026-10-21T10:02:00Z" })).length, 1);
});

test("browser file reader ingests a gzip access log", async () => {
  const line = '203.0.113.5 - - [21/Oct/2026:10:24:36 +0000] "GET /wp-login.php HTTP/1.1" 200 100 "-" "Mozilla/5.0"';
  const file = new File([gzipSync(line)], "access.log.gz", { type: "application/gzip" });
  const builder = new AnalysisBuilder();
  await ingestBrowserFile(file, builder);
  const result = builder.finish();
  assert.equal(result.accessCount, 1);
  assert.equal(result.sources[0], "access.log.gz");
});

test("browser reader accepts a real extensionless cPanel error_log", async () => {
  const data = await readFile(new URL("./fixtures/error_log", import.meta.url));
  const builder = new AnalysisBuilder();
  await ingestBrowserFile(new File([data], "error_log"), builder);
  const result = builder.finish();
  assert.equal(result.errorCount, 41_741);
  assert.equal(result.skippedLines, 0);
  assert.ok(result.findings.some(f => f.id.startsWith("fatal-") && /null or false/.test(f.explanation)));
});

test("gzip detection works without a filename extension", async () => {
  const line = "[21-Oct-2026 09:15:14 UTC] PHP Fatal error: Uncaught Error in /home/site/wp-content/plugins/shop/pay.php on line 20";
  const builder = new AnalysisBuilder();
  await ingestBrowserFile(new File([gzipSync(line)], "error_log"), builder);
  assert.equal(builder.finish().errorCount, 1);
});

test("large logs retain bounded evidence while scanning all records", () => {
  const builder = new AnalysisBuilder();
  const normal = '203.0.113.5 - - [21/Oct/2026:10:24:36 +0000] "GET / HTTP/1.1" 200 100 "-" "Test"';
  for (let line = 1; line <= 120_005; line++) builder.add(normal, "access_log", line);
  builder.add('203.0.113.5 - - [21/Oct/2026:10:24:37 +0000] "GET /late HTTP/1.1" 503 100 "-" "Test"', "access_log", 120_006);
  const result = builder.finish();
  assert.equal(result.parsedCount, 120_006);
  assert.equal(result.accessCount, 120_006);
  assert.equal(result.statusCounts["5xx"], 1);
  assert.equal(result.events.length, 120_000);
  assert.ok(result.events.some(e => e.path === "/late"));
  assert.equal(result.truncated, true);
  assert.match(buildResponse(result).text, /first 100,000 and last 20,000/);
});

test("high-cardinality access logs bound aggregate memory and label estimates", () => {
  const builder = new AnalysisBuilder();
  for (let i = 0; i < 100_001; i++) {
    builder.add(`ip-${i} - - [21/Oct/2026:10:24:36 +0000] "GET /item/${i} HTTP/1.1" 200 100 "-" "Test"`, "access_log", i + 1);
  }
  const result = builder.finish();
  assert.equal(result.accessCount, 100_001);
  assert.equal(result.topCountsApproximate, true);
  assert.equal(result.uniqueIpsApproximate, true);
  assert.ok(result.uniqueIps > 80_000 && result.uniqueIps < 120_000);
  assert.match(buildResponse(result).text, /distinct-IP count is an estimate/);
});

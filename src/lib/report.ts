import type { Analysis, Finding } from "./analyzer";

export interface ReportResponse {
  headline: string;
  summary: string;
  findings: { title: string; severity: string; evidence: string; explanation: string; nextSteps: string[] }[];
  coverage: string[];
  text: string;
}

function findingResponse(finding: Finding) {
  return {
    title: finding.title,
    severity: finding.severity,
    evidence: finding.summary,
    explanation: finding.explanation,
    nextSteps: finding.nextSteps,
  };
}

export function buildResponse(analysis: Analysis): ReportResponse {
  const coverage: string[] = [];
  if (!analysis.accessCount) coverage.push("No access records were parsed, so request, IP, status-code, and attack-pattern analysis is unavailable.");
  if (!analysis.errorCount) coverage.push("No application or server error records were parsed; 5xx causes cannot be determined from access records alone.");
  if (analysis.undatedCount) coverage.push(`${analysis.undatedCount} error records lack a known timezone and were excluded from the timeline. Supply the server timezone to correlate them with requests.`);
  if (analysis.skippedLines) coverage.push(`${analysis.skippedLines} nonblank lines were not recognized. Check the import-quality examples before relying on the totals.`);
  if (analysis.truncated) coverage.push(`All ${analysis.parsedCount.toLocaleString()} records were scanned for summary totals. Findings and evidence use the first 100,000 and last 20,000 records, so incidents in between may be missed.`);
  if (analysis.uniqueIpsApproximate) coverage.push("The distinct-IP count is an estimate because this log contains over 100,000 IPs.");
  if (analysis.topCountsApproximate) coverage.push("Some top path, IP, or user-agent counts may be lower bounds because the number of distinct values exceeded the memory budget.");
  if (analysis.userAgentsGroupedByPrefix) coverage.push("User-agent strings longer than 256 characters were grouped by their first 256 characters.");
  coverage.push("Access responses do not confirm successful logins, executed payloads, or a proven root cause.");

  if (!analysis.parsedCount) {
    const headline = "No supported log records found";
    const summary = `Read ${analysis.totalLines} lines from ${analysis.sources.length} ${analysis.sources.length === 1 ? "source" : "sources"}, but could not parse access or error events.`;
    return { headline, summary, findings: [], coverage, text: [headline, summary, ...coverage].join("\n\n") };
  }

  const critical = analysis.findings.filter(f => f.severity === "critical" || f.severity === "high").length;
  const headline = critical ? `${critical} high-priority finding${critical === 1 ? "" : "s"} in the supplied logs` : analysis.findings.length ? `${analysis.findings.length} finding${analysis.findings.length === 1 ? "" : "s"} in the supplied logs` : "No detector findings in the supplied logs";
  const summary = `${analysis.accessCount.toLocaleString()} access ${analysis.accessCount === 1 ? "request" : "requests"}, ${analysis.errorCount.toLocaleString()} error ${analysis.errorCount === 1 ? "record" : "records"}, and ${(analysis.statusCounts["5xx"] || 0).toLocaleString()} HTTP 5xx ${analysis.statusCounts["5xx"] === 1 ? "response" : "responses"} were parsed from ${analysis.sources.length} ${analysis.sources.length === 1 ? "source" : "sources"}.`;
  const findings = analysis.findings.map(findingResponse);
  const parts = [headline, summary];
  if (analysis.accessCount) parts.push(`## Access overview\n${analysis.uniqueIpsApproximate ? "About " : ""}${analysis.uniqueIps.toLocaleString()} recorded IPs; ${(analysis.statusCounts["4xx"] || 0).toLocaleString()} HTTP 4xx ${(analysis.statusCounts["4xx"] || 0) === 1 ? "response" : "responses"}.\nTop paths: ${analysis.topPaths.slice(0, 5).map(item => `${item.label} (${item.count})`).join(", ") || "none"}.\nTop recorded IPs: ${analysis.topIps.slice(0, 5).map(item => `${item.label} (${item.count})`).join(", ") || "none"}.\nTop user agents: ${analysis.topUserAgents.slice(0, 5).map(item => `${item.label} (${item.count})`).join(", ") || "not recorded"}.\nTop HTTP statuses: ${analysis.topStatusCodes.slice(0, 5).map(item => `${item.label} (${item.count})`).join(", ") || "none"}.`);
  for (const finding of findings) parts.push(`## ${finding.title} (${finding.severity})\n${finding.evidence}\n${finding.explanation}\nNext checks:\n${finding.nextSteps.map(step => `- ${step}`).join("\n")}`);
  parts.push(`## Coverage and limits\n${coverage.map(item => `- ${item}`).join("\n")}`);
  return { headline, summary, findings, coverage, text: parts.join("\n\n") };
}

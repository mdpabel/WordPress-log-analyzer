"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import type { Analysis, Finding, LogEvent } from "@/lib/analyzer";
import { matchesInvestigation, type ActivityFilter } from "@/lib/investigation";
import { demoLog } from "@/lib/demo";
import { buildResponse } from "@/lib/report";
import { trackEvent } from "@/lib/analytics";

const PAGE_SIZE = 25;

function formatSize(bytes: number): string {
  return bytes < 1024 * 1024 ? `${Math.ceil(bytes / 1024)} KB` : `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

function formatDate(value: string | null): string {
  return value ? new Date(value).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }) : "Time unavailable";
}

function saveFile(name: string, content: string, type: string): void {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  link.click();
  trackEvent(type === "text/csv" ? "log_lines_downloaded" : "report_downloaded", { format: type === "text/csv" ? "csv" : "markdown" });
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function csv(rows: (string | number | undefined | null)[][]): string {
  return rows.map(row => row.map(value => `"${String(value ?? "").replaceAll('"', '""')}"`).join(",")).join("\r\n");
}

function FindingItem({ finding, first, onEvidence }: { finding: Finding; first: boolean; onEvidence: (finding: Finding) => void }) {
  const [open, setOpen] = useState(first);
  return <details className="finding" open={open} onToggle={event => setOpen(event.currentTarget.open)}>
    <summary>
      <span className={`severity severity-${finding.severity}`}>{finding.severity}</span>
      <span className="finding-title"><strong>{finding.title}</strong><span>{finding.summary}</span></span>
      <span className="finding-toggle" aria-hidden="true">⌄</span>
    </summary>
    <div className="finding-body">
      <p>{finding.explanation}</p>
      <h3>What to check next</h3>
      <ol>{finding.nextSteps.map(step => <li key={step}>{step}</li>)}</ol>
      {finding.eventIds.length > 0 && <button className="link-button" onClick={() => onEvidence(finding)}>View supporting log lines →</button>}
    </div>
  </details>;
}

function EventItem({ event, onTraceIp }: { event: LogEvent; onTraceIp: (ip: string) => void }) {
  return <details className="event">
    <summary>
      <span className={`event-code ${event.kind === "error" ? "error-code" : ""}`}>{event.kind === "access" ? event.status || "HTTP" : event.level || "Error"}</span>
      <span className="event-message">{event.kind === "access" ? `${event.method || ""} ${event.path || "Unknown path"}` : event.message || "Error record"}</span>
      <span className="event-date">{formatDate(event.timestamp)}</span>
    </summary>
    <div className="event-body"><span>{event.source}, line {event.line}{event.ip ? ` · ${event.ip}` : ""}</span>{event.ip && <button className="trace-button" onClick={() => onTraceIp(event.ip!)}>Trace this IP</button>}<pre>{event.raw}</pre></div>
  </details>;
}

function TopItems({ title, items, empty, onPick }: { title: string; items: { label: string; count: number }[]; empty?: string; onPick: (label: string) => void }) {
  return <div className="top-card"><h3>{title}</h3>{items.length ? <ol>{items.slice(0, 5).map(item => <li key={item.label}><button onClick={() => onPick(item.label)} title={`Show log lines for ${item.label}`}><span>{item.label}</span><strong>{item.count.toLocaleString()}</strong></button></li>)}</ol> : <p>{empty || "No records"}</p>}</div>;
}

export default function Analyzer() {
  const [files, setFiles] = useState<File[]>([]);
  const [pasted, setPasted] = useState("");
  const [timezoneOffset, setTimezoneOffset] = useState("");
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState("");
  const [error, setError] = useState("");
  const [pdfBusy, setPdfBusy] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [showRecords, setShowRecords] = useState(false);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [search, setSearch] = useState("");
  const [kind, setKind] = useState("all");
  const [status, setStatus] = useState("all");
  const [exactStatus, setExactStatus] = useState("");
  const [sourceIp, setSourceIp] = useState("");
  const [exactPath, setExactPath] = useState("");
  const [userAgent, setUserAgent] = useState("");
  const [activity, setActivity] = useState<ActivityFilter>("all");
  const [fromTime, setFromTime] = useState("");
  const [toTime, setToTime] = useState("");
  const [page, setPage] = useState(0);
  const fileInput = useRef<HTMLInputElement>(null);
  const worker = useRef<Worker | null>(null);
  const resultsRef = useRef<HTMLElement>(null);
  const recordsRef = useRef<HTMLElement>(null);

  useEffect(() => () => worker.current?.terminate(), []);

  function addFiles(incoming: FileList | File[]): void {
    const selected = Array.from(incoming);
    if (!selected.length) return;
    trackEvent("logs_files_selected", { file_count: Math.min(selected.length, 12 - files.length) });
    if (files.length + selected.length > 12) setError("You can analyze up to 12 files at once.");
    else setError("");
    setFiles(current => [...current, ...selected].slice(0, 12));
  }

  function run(demo = false): void {
    const text = demo ? demoLog : pasted;
    if (!text.trim() && !files.length) { setError("Choose a log file or paste log text first."); return; }
    const offset = timezoneOffset.trim();
    if (offset && !/^[+-](?:0\d|1[0-4]):[0-5]\d$/.test(offset)) { setError("Use a timezone offset like +06:00, or leave it blank."); return; }
    trackEvent("logs_analysis_started", {
      input_type: demo ? "sample" : files.length && text.trim() ? "files_and_paste" : files.length ? "files" : "paste",
      file_count: demo ? 0 : files.length,
      has_timezone: Boolean(offset),
    });
    const assumedOffsetMinutes = offset ? (Number(offset.slice(1, 3)) * 60 + Number(offset.slice(4, 6))) * (offset[0] === "+" ? 1 : -1) : null;
    worker.current?.terminate();
    setBusy(true);
    setProgress("Reading logs…");
    setError("");
    setAnalysis(null);
    const instance = new Worker("/analyzer-worker.js");
    worker.current = instance;
    instance.onmessage = (message: MessageEvent<{ type: string; analysis?: Analysis; message?: string }>) => {
      const result = message.data;
      if (result.type === "progress") setProgress(result.message || "Analyzing…");
      if (result.type === "error") {
        trackEvent("logs_analysis_failed", { stage: "worker" });
        setError(result.message || "Analysis failed."); setBusy(false); instance.terminate();
      }
      if (result.type === "result" && result.analysis) {
        trackEvent("logs_analysis_completed", {
          parsed_records: result.analysis.parsedCount,
          access_records: result.analysis.accessCount,
          error_records: result.analysis.errorCount,
          finding_count: result.analysis.findings.length,
          priority_findings: result.analysis.findings.filter(finding => finding.severity === "critical" || finding.severity === "high").length,
          truncated: result.analysis.truncated,
          skipped_lines: result.analysis.skippedLines,
        });
        setAnalysis(result.analysis);
        setBusy(false);
        setShowRecords(false);
        setSelectedFinding(null);
        setPage(0);
        if (demo) { setFiles([]); setPasted(""); }
        instance.terminate();
        window.setTimeout(() => resultsRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }), 80);
      }
    };
    instance.onerror = () => {
      trackEvent("logs_analysis_failed", { stage: "worker_start" });
      setError("The analyzer could not start. Refresh the page and try again."); setBusy(false); instance.terminate();
    };
    instance.postMessage({ files: demo ? [] : files, pasted: text, assumedOffsetMinutes });
  }

  function startOver(): void {
    trackEvent("new_analysis_started");
    worker.current?.terminate();
    setAnalysis(null);
    setFiles([]);
    setPasted("");
    setTimezoneOffset("");
    setShowRecords(false);
    setSelectedFinding(null);
    setError("");
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  function showEvidence(finding: Finding | null): void {
    trackEvent("evidence_viewed", { scope: finding ? "finding" : "all" });
    setSelectedFinding(finding);
    setShowRecords(true);
    clearRecordFilters();
    window.setTimeout(() => recordsRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }), 80);
  }

  function clearRecordFilters(): void {
    setSearch(""); setKind("all"); setStatus("all"); setExactStatus("");
    setSourceIp(""); setExactPath(""); setUserAgent(""); setActivity("all"); setFromTime(""); setToTime(""); setPage(0);
  }

  function traceIp(ip: string): void {
    trackEvent("ip_trace_viewed");
    inspectTop("ip", ip);
  }

  function inspectTop(field: "ip" | "path" | "userAgent" | "status", value: string): void {
    trackEvent("traffic_breakdown_viewed", { dimension: field });
    setSelectedFinding(null);
    setShowRecords(true);
    clearRecordFilters();
    if (field === "ip") setSourceIp(value);
    if (field === "path") setExactPath(value);
    if (field === "userAgent") setUserAgent(value);
    if (field === "status") setExactStatus(value);
    window.setTimeout(() => recordsRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }), 80);
  }

  async function savePdf(): Promise<void> {
    if (!analysis || pdfBusy) return;
    setPdfBusy(true);
    setError("");
    try {
      const { downloadReportPdf } = await import("@/lib/pdf-report");
      await downloadReportPdf(analysis);
      trackEvent("report_downloaded", { format: "pdf" });
    } catch {
      trackEvent("report_download_failed", { format: "pdf" });
      setError("Could not create the PDF. Please try again.");
    } finally {
      setPdfBusy(false);
    }
  }

  const filtered = useMemo(() => {
    if (!analysis) return [];
    const evidenceIds = selectedFinding ? new Set(selectedFinding.eventIds) : null;
    return analysis.events.filter(event => {
      if (evidenceIds && !evidenceIds.has(event.id)) return false;
      return matchesInvestigation(event, { search, kind, status, exactStatus, ip: sourceIp, path: exactPath, userAgent, activity, fromTime, toTime });
    });
  }, [analysis, selectedFinding, search, kind, status, exactStatus, sourceIp, exactPath, userAgent, activity, fromTime, toTime]);
  const visible = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
  const report = analysis ? buildResponse(analysis) : null;

  return <div id="tool" className="shell main-content">
      {!analysis && <>
        <div className="intro"><span className="eyebrow">PRIVATE, BROWSER-BASED TOOL</span><h1>WordPress log analyzer for access and error logs.</h1><p>Paste logs or add files from cPanel, a VPS, or your host. Find suspicious requests, PHP fatal errors, traffic patterns, and the lines behind each finding.</p></div>
        <section className="input-card" aria-label="Add logs">
          <div className="section-heading"><span className="step-number">1</span><div><h2>Add your logs</h2><p>Choose files from cPanel or your server, or paste log lines below.</p></div></div>
          <input ref={fileInput} className="sr-only" type="file" multiple onChange={event => { if (event.target.files) addFiles(event.target.files); event.target.value = ""; }} />
          <div className={`dropzone ${dragging ? "dragging" : ""}`} onDragOver={event => { event.preventDefault(); setDragging(true); }} onDragLeave={() => setDragging(false)} onDrop={event => { event.preventDefault(); setDragging(false); addFiles(event.dataTransfer.files); }}>
            <div className="upload-symbol" aria-hidden="true">↑</div><strong>Drop log files here</strong><span>or <button className="inline-button" onClick={() => fileInput.current?.click()}>choose files</button></span><small>Access logs, error_log, debug.log, and gzip · up to 512 MB per file</small>
          </div>
          {files.length > 0 && <ul className="selected-files">{files.map((file, index) => <li key={`${file.name}-${index}`}><span><strong>{file.name}</strong><small>{formatSize(file.size)}</small></span><button aria-label={`Remove ${file.name}`} onClick={() => setFiles(current => current.filter((_, i) => i !== index))}>Remove</button></li>)}</ul>}
          <div className="or-divider"><span>or paste log text</span></div>
          <textarea className="paste-input" value={pasted} onChange={event => setPasted(event.target.value)} placeholder="Paste access or error log lines here…" rows={5} aria-label="Paste log text" />
          <details className="timezone-option"><summary>Server timezone (optional)</summary><label>If your error log has no timezone, enter its UTC offset.<input value={timezoneOffset} onChange={event => setTimezoneOffset(event.target.value)} placeholder="Example: +06:00" aria-label="Server timezone offset" /></label></details>
          <div className="form-actions"><button className="primary-button" disabled={busy} onClick={() => run()}>{busy ? progress : "Analyze logs"}</button><button className="quiet-button" disabled={busy} onClick={() => run(true)}>Try with sample logs</button></div>
          {error && <p className="form-error" role="alert">{error}</p>}
          <p className="privacy-note">Your files are processed in this browser. They are not uploaded to a server.</p>
        </section>
        <div className="help-line"><span>What will I see?</span> A summary, likely issues, practical next steps, and the log lines behind each finding.</div>
      </>}

      {analysis && report && <section ref={resultsRef} className="results" aria-label="Analysis results">
        <div className="results-top"><div><span className="eyebrow">ANALYSIS COMPLETE</span><h1>{report.headline}</h1><p>{report.summary}</p></div><button className="outline-button" onClick={startOver}>Analyze another log</button></div>
        <div className="report-actions"><button className="primary-button" disabled={pdfBusy} onClick={savePdf}>{pdfBusy ? "Creating PDF…" : "Download PDF report"}</button><button className="quiet-button" onClick={() => saveFile("logscope-report.md", report.text, "text/markdown")}>Download text report</button></div>
        {error && <p className="form-error" role="alert">{error}</p>}
        <div className="result-metrics"><div><strong>{analysis.parsedCount.toLocaleString()}</strong><span>log records</span></div><div><strong>{analysis.accessCount.toLocaleString()}</strong><span>access requests</span></div><div><strong>{analysis.errorCount.toLocaleString()}</strong><span>error records</span></div><div><strong>{(analysis.statusCounts["5xx"] || 0).toLocaleString()}</strong><span>5xx responses</span></div></div>
        {analysis.truncated && <div className="important-note"><strong>Some findings may be missing.</strong> All records contributed to summary totals, but findings use retained evidence from the beginning and end of a very large log.</div>}
        {analysis.skippedLines > 0 && <div className="important-note"><strong>{analysis.skippedLines.toLocaleString()} lines were not recognized.</strong> Check the import details below before relying on the totals.</div>}
        <section className="findings-section" aria-label="Findings"><div className="section-heading"><span className="step-number">2</span><div><h2>What we found</h2><p>Open a finding for an explanation and next steps.</p></div></div>{analysis.findings.length > 0 ? <div className="finding-list">{analysis.findings.map((finding, index) => <FindingItem key={finding.id} finding={finding} first={index === 0} onEvidence={showEvidence} />)}</div> : <div className="empty-card">No detector findings in these logs. You can still browse the parsed lines below.</div>}</section>
        {analysis.accessCount > 0 && <section className="traffic-section" aria-label="Access traffic"><div className="section-heading"><span className="step-number">3</span><div><h2>Most requested</h2><p>Counts cover all parsed access records. Select a row to inspect matching log lines.</p></div></div><div className="top-grid"><TopItems title="Source IPs" items={analysis.topIps} onPick={value => inspectTop("ip", value)} /><TopItems title="Requested paths" items={analysis.topPaths} onPick={value => inspectTop("path", value)} /><TopItems title="User agents" items={analysis.topUserAgents} empty="Not recorded in these access logs" onPick={value => inspectTop("userAgent", value)} /><TopItems title="HTTP status codes" items={analysis.topStatusCodes} onPick={value => inspectTop("status", value)} /></div><p className="traffic-note">{analysis.uniqueIpsApproximate ? "About " : ""}{analysis.uniqueIps.toLocaleString()} distinct IPs. User agents are browser-reported strings and do not establish identity.{analysis.truncated ? " Matching lines are limited to retained evidence from the beginning and end of this large log." : ""}{analysis.topCountsApproximate ? " Some top counts may be lower bounds." : ""}</p></section>}
        <details className="more-details"><summary>Import quality and limits <span>View source coverage and unrecognized lines</span></summary><div className="more-body"><div className="detail-grid"><div><h3>Log coverage</h3><p>{analysis.totalLines.toLocaleString()} lines read from {analysis.sources.length} source{analysis.sources.length === 1 ? "" : "s"}.</p><p>{analysis.skippedLines.toLocaleString()} unrecognized ? {analysis.undatedCount.toLocaleString()} without a known timezone</p><p>Records span {formatDate(analysis.startedAt)} to {formatDate(analysis.endedAt)}.</p></div><div><h3>Things to know</h3><ul className="coverage-list">{report.coverage.map(note => <li key={note}>{note}</li>)}</ul></div></div>{analysis.unparsedExamples.length > 0 && <details className="unparsed"><summary>Show unrecognized line examples</summary>{analysis.unparsedExamples.map(example => <pre key={`${example.source}-${example.line}`}>{example.source}:{example.line} {example.raw}</pre>)}</details>}</div></details>
        <section ref={recordsRef} className="records-section" aria-label="Log lines"><div className="records-heading"><div><h2>{selectedFinding ? `Log lines: ${selectedFinding.title}` : "Browse log lines"}</h2><p>Open a line to see its source and full recorded text.</p></div><button className="outline-button" onClick={() => { if (!showRecords) showEvidence(null); else if (selectedFinding) showEvidence(null); else setShowRecords(false); }}>{showRecords ? selectedFinding ? "Show all lines" : "Hide log lines" : "Browse log lines"}</button></div>{showRecords && <div className="records-card"><div className="record-filters"><input value={search} onChange={event => { setSearch(event.target.value); setPage(0); }} placeholder="Search message, IP, path…" aria-label="Search log lines" /><select value={kind} onChange={event => { setKind(event.target.value); setPage(0); }} aria-label="Log type"><option value="all">All types</option><option value="access">Access</option><option value="error">Error</option></select><select value={status} onChange={event => { setStatus(event.target.value); setPage(0); }} aria-label="HTTP status"><option value="all">All statuses</option><option value="2xx">2xx</option><option value="3xx">3xx</option><option value="4xx">4xx</option><option value="5xx">5xx</option></select></div><details className="investigation-options"><summary>Investigate by IP, time, or activity</summary><div className="investigation-grid"><label>Source IP<input value={sourceIp} onChange={event => { setSourceIp(event.target.value); setPage(0); }} placeholder="Exact IP address" /></label><label>Requested path<input value={exactPath} onChange={event => { setExactPath(event.target.value); setPage(0); }} placeholder="Exact path" /></label><label>User agent starts with<input value={userAgent} onChange={event => { setUserAgent(event.target.value); setPage(0); }} placeholder="User agent" /></label><label>Exact HTTP status<input value={exactStatus} onChange={event => { setExactStatus(event.target.value); setPage(0); }} inputMode="numeric" maxLength={3} placeholder="For example, 200" /></label><label>Activity<select value={activity} onChange={event => { setActivity(event.target.value as ActivityFilter); setPage(0); }}><option value="all">All activity</option><option value="probes">Suspicious probes</option><option value="login">Login / XML-RPC</option><option value="post">POST requests</option><option value="uploads-php">PHP requested in uploads</option></select></label><label>From<input type="datetime-local" value={fromTime} onChange={event => { setFromTime(event.target.value); setPage(0); }} /></label><label>Until<input type="datetime-local" value={toTime} onChange={event => { setToTime(event.target.value); setPage(0); }} /></label></div><button className="link-button" onClick={() => { setSelectedFinding(null); clearRecordFilters(); }}>Clear investigation filters</button><p>Times use your device's timezone. These records show requests, not POST bodies or proof that a file changed.</p></details><div className="record-toolbar"><span>{filtered.length.toLocaleString()} matching lines{analysis.truncated ? " in retained evidence" : ""}</span><button className="link-button" onClick={() => saveFile("logscope-lines.csv", csv([["time", "source", "line", "type", "ip", "method", "path", "status", "level", "component", "raw"], ...filtered.map(event => [event.timestamp, event.source, event.line, event.kind, event.ip, event.method, event.path, event.status, event.level, event.component, event.raw])]), "text/csv")}>Download CSV</button></div><div className="event-list">{visible.map(event => <EventItem key={event.id} event={event} onTraceIp={traceIp} />)}{visible.length === 0 && <p className="empty-lines">No lines match these filters.</p>}</div><div className="pagination"><button disabled={page === 0} onClick={() => setPage(current => current - 1)}>← Previous</button><span>Page {page + 1} of {Math.max(1, Math.ceil(filtered.length / PAGE_SIZE))}</span><button disabled={(page + 1) * PAGE_SIZE >= filtered.length} onClick={() => setPage(current => current + 1)}>Next →</button></div></div>}</section>
      </section>}
  </div>;
}

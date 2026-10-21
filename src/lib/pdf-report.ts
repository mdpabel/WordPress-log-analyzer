import { jsPDF } from "jspdf";
import type { Analysis } from "./analyzer";
import { buildResponse } from "./report";

function printable(value: string): string {
  return value
    .replace(/[\u2018\u2019]/g, "'")
    .replace(/[\u201c\u201d]/g, '"')
    .replace(/[\u2013\u2014]/g, "-")
    .replace(/\u2026/g, "...")
    .replace(/[\r\n\t]+/g, " ")
    .replace(/[^\x20-\x7e\xa0-\xff]/g, "?");
}

export function createReportPdf(analysis: Analysis): jsPDF {
  const report = buildResponse(analysis);
  const doc = new jsPDF({ unit: "pt", format: "a4", compress: true });
  const width = doc.internal.pageSize.getWidth();
  const height = doc.internal.pageSize.getHeight();
  const margin = 48;
  const contentWidth = width - margin * 2;
  let y = 54;
  let activeFinding: string | null = null;

  function needSpace(amount: number): void {
    if (y + amount > height - 58) {
      doc.addPage();
      y = 52;
      if (activeFinding) paragraph(`${activeFinding} (continued)`, { size: 10, color: [23, 40, 58], bold: true, gap: 9 });
    }
  }

  function paragraph(value: string, options: { size?: number; color?: [number, number, number]; bold?: boolean; indent?: number; gap?: number } = {}): void {
    const { size = 10, color = [57, 77, 88], bold = false, indent = 0, gap = 9 } = options;
    doc.setFont("helvetica", bold ? "bold" : "normal");
    doc.setFontSize(size);
    doc.setTextColor(...color);
    const lines = doc.splitTextToSize(printable(value), contentWidth - indent) as string[];
    const lineHeight = size * 1.42;
    for (const line of lines) { needSpace(lineHeight); doc.text(line, margin + indent, y); y += lineHeight; }
    y += gap;
  }

  function section(title: string): void {
    needSpace(47);
    y += 10;
    doc.setDrawColor(219, 230, 230);
    doc.line(margin, y, width - margin, y);
    y += 21;
    paragraph(title, { size: 14, color: [23, 40, 58], bold: true, gap: 7 });
  }

  doc.setFillColor(16, 111, 114);
  doc.rect(0, 0, width, 10, "F");
  paragraph("LOGSCOPE / WORDPRESS LOG REPORT", { size: 9, color: [16, 111, 114], bold: true, gap: 14 });
  paragraph(report.headline, { size: 20, color: [23, 40, 58], bold: true, gap: 10 });
  paragraph(report.summary, { size: 10.5, gap: 7 });
  paragraph(`Generated ${new Date().toLocaleString()}  |  ${analysis.parsedCount.toLocaleString()} parsed records  |  ${analysis.sources.length} ${analysis.sources.length === 1 ? "source" : "sources"}`, { size: 8.5, color: [110, 127, 137], gap: 4 });

  section("Findings and next steps");
  if (!analysis.findings.length) paragraph("No detector findings were found in the supplied logs. Review the source coverage and import quality below.");
  const evidence = new Map(analysis.events.map(event => [event.id, event]));
  for (const finding of analysis.findings) {
    activeFinding = null;
    needSpace(100);
    activeFinding = finding.title;
    paragraph(`${finding.title}  |  ${finding.severity.toUpperCase()}  |  ${finding.count.toLocaleString()} ${finding.count === 1 ? "occurrence" : "occurrences"}`, { size: 11, color: [23, 40, 58], bold: true, gap: 7 });
    paragraph(finding.summary, { gap: 6 });
    paragraph(finding.explanation, { gap: 6 });
    for (const [index, step] of finding.nextSteps.entries()) paragraph(`${index + 1}. ${step}`, { indent: 9, gap: 3 });
    const samples = finding.eventIds.slice(0, 2).map(id => evidence.get(id)).filter(event => event !== undefined);
    if (samples.length) {
      y += 3;
      paragraph("Example log lines", { size: 9, color: [16, 111, 114], bold: true, gap: 5 });
      for (const event of samples) paragraph(`${event.source}:${event.line}  ${event.raw.slice(0, 330)}`, { size: 8.2, color: [94, 109, 117], indent: 9, gap: 5 });
    }
    y += 10;
  }
  activeFinding = null;

  if (analysis.accessCount) {
    section("Top access traffic");
    const summarize = (items: { label: string; count: number }[]) => items.slice(0, 5).map(item => `${item.label} (${item.count.toLocaleString()})`).join(", ") || "Not recorded";
    paragraph(`Source IPs: ${summarize(analysis.topIps)}`, { size: 9.2, gap: 5 });
    paragraph(`Requested paths: ${summarize(analysis.topPaths)}`, { size: 9.2, gap: 5 });
    paragraph(`User agents: ${summarize(analysis.topUserAgents)}`, { size: 9.2, gap: 5 });
    paragraph(`HTTP status codes: ${summarize(analysis.topStatusCodes)}`, { size: 9.2, gap: 5 });
  }

  needSpace(105);
  section("Coverage and limits");
  for (const note of report.coverage) paragraph(`- ${note}`, { size: 9.4, indent: 9, gap: 5 });
  paragraph(`Sources: ${analysis.sources.join(", ") || "none"}`, { size: 9.4, gap: 5 });

  const pages = doc.getNumberOfPages();
  for (let number = 1; number <= pages; number++) {
    doc.setPage(number);
    doc.setDrawColor(219, 230, 230);
    doc.line(margin, height - 44, width - margin, height - 44);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(8);
    doc.setTextColor(127, 143, 150);
    doc.text("LogScope | Analysis of supplied logs", margin, height - 30);
    doc.text(`${number} / ${pages}`, width - margin, height - 30, { align: "right" });
  }
  return doc;
}

export async function downloadReportPdf(analysis: Analysis): Promise<void> {
  createReportPdf(analysis).save("logscope-report.pdf");
}

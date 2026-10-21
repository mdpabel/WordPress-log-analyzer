import test from "node:test";
import assert from "node:assert/strict";
import { analyzeText } from "../src/lib/analyzer";
import { demoLog } from "../src/lib/demo";
import { createReportPdf } from "../src/lib/pdf-report";

test("creates a PDF report with findings, top traffic, and coverage", () => {
  const pdf = createReportPdf(analyzeText(demoLog));
  const bytes = new Uint8Array(pdf.output("arraybuffer"));
  assert.equal(new TextDecoder().decode(bytes.slice(0, 4)), "%PDF");
  assert.ok(bytes.byteLength > 1000);
  assert.ok(pdf.getNumberOfPages() <= 3);
});

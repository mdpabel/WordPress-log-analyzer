/// <reference lib="webworker" />
import { AnalysisBuilder } from "./analyzer";
import { ingestBrowserFile } from "./import";

type Request = { files: File[]; pasted: string; assumedOffsetMinutes: number | null };
const MAX_PASTE_CHARS = 2_000_000;

self.onmessage = async (event: MessageEvent<Request>) => {
  try {
    const { files, pasted, assumedOffsetMinutes } = event.data;
    if (pasted.length > MAX_PASTE_CHARS) throw new Error("Pasted text exceeds the current 2 million character limit.");
    const builder = new AnalysisBuilder(assumedOffsetMinutes);
    if (pasted.trim()) pasted.split(/\r?\n/).forEach((line, index) => builder.add(line, "pasted log", index + 1));
    for (const file of files) {
      self.postMessage({ type: "progress", message: `Reading ${file.name}…` });
      await ingestBrowserFile(file, builder, bytes => self.postMessage({ type: "progress", message: `Reading ${file.name}: ${Math.round(bytes / 1024 / 1024)} MB processed…` }));
    }
    self.postMessage({ type: "result", analysis: builder.finish() });
  } catch (error) {
    self.postMessage({ type: "error", message: error instanceof Error ? error.message : "Could not analyze these logs." });
  }
};

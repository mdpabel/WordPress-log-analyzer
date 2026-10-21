import { AnalysisBuilder } from "./analyzer";

export const MAX_FILE_BYTES = 512 * 1024 * 1024;
export const MAX_EXPANDED_BYTES = 1024 * 1024 * 1024;
const MAX_LINE_CHARS = 1_000_000;

export async function ingestBrowserFile(file: File, builder: AnalysisBuilder, onProgress?: (expandedBytes: number) => void): Promise<void> {
  if (file.size > MAX_FILE_BYTES) throw new Error(`${file.name} exceeds the current 512 MB file limit. Use the CLI for larger files.`);
  const header = new Uint8Array(await file.slice(0, 4096).arrayBuffer());
  const gzip = header[0] === 0x1f && header[1] === 0x8b;
  if (!gzip && (header.includes(0) || (header[0] === 0x50 && header[1] === 0x4b))) {
    throw new Error(`${file.name} is a binary file or unsupported archive. Select a plain-text or gzip log.`);
  }
  let stream: ReadableStream<Uint8Array> = file.stream();
  if (gzip) stream = stream.pipeThrough(new DecompressionStream("gzip") as unknown as TransformStream<Uint8Array, Uint8Array>);
  const reader = stream.getReader();
  const decoder = new TextDecoder();
  let carry = "";
  let bytes = 0;
  let nextProgress = 16 * 1024 * 1024;
  let lineNumber = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    bytes += value.byteLength;
    if (bytes > MAX_EXPANDED_BYTES) { await reader.cancel(); throw new Error(`${file.name} exceeds the 1 GB expanded-data limit. Use the CLI for larger files.`); }
    if (bytes >= nextProgress) { onProgress?.(bytes); nextProgress = bytes + 16 * 1024 * 1024; }
    carry += decoder.decode(value, { stream: true });
    let newline = carry.indexOf("\n");
    while (newline !== -1) {
      builder.add(carry.slice(0, newline).replace(/\r$/, ""), file.name, ++lineNumber);
      carry = carry.slice(newline + 1);
      newline = carry.indexOf("\n");
    }
    if (carry.length > MAX_LINE_CHARS) { await reader.cancel(); throw new Error(`${file.name} contains a line over 1 million characters; check that it is a text log.`); }
  }
  carry += decoder.decode();
  if (carry) builder.add(carry, file.name, ++lineNumber);
}

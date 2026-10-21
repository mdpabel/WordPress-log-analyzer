import { createReadStream } from "node:fs";
import { open } from "node:fs/promises";
import { basename } from "node:path";
import { createGunzip } from "node:zlib";
import { createInterface } from "node:readline";
import { AnalysisBuilder } from "../src/lib/analyzer";
import { buildResponse } from "../src/lib/report";

const args = process.argv.slice(2);
if (args.includes("--help") || args.includes("-h")) {
  console.log("Usage: npm run analyze -- [--timezone +06:00] [--json] [log-file ...]\nPlain-text logs may have any filename. Gzip is detected from its contents. With no files, reads pasted log text from stdin.");
  process.exit(0);
}

let offsetMinutes: number | null = null;
const timezoneIndex = args.indexOf("--timezone");
if (timezoneIndex !== -1) {
  const value = args[timezoneIndex + 1] || "";
  if (!/^[+-](?:0\d|1[0-4]):[0-5]\d$/.test(value)) {
    console.error("Invalid timezone offset. Use a value such as +06:00.");
    process.exit(2);
  }
  offsetMinutes = (Number(value.slice(1, 3)) * 60 + Number(value.slice(4, 6))) * (value[0] === "+" ? 1 : -1);
  args.splice(timezoneIndex, 2);
}
const jsonIndex = args.indexOf("--json");
const json = jsonIndex !== -1;
if (json) args.splice(jsonIndex, 1);
if (args.some(arg => arg.startsWith("--"))) {
  console.error("Unknown option. Run with --help for usage.");
  process.exit(2);
}

const builder = new AnalysisBuilder(offsetMinutes);
async function ingest(stream: NodeJS.ReadableStream, source: string): Promise<void> {
  const lines = createInterface({ input: stream, crlfDelay: Infinity });
  let number = 0;
  for await (const line of lines) builder.add(line, source, ++number);
}

async function main(): Promise<void> {
  try {
    if (!args.length) {
      await ingest(process.stdin, "stdin");
    } else {
      for (const path of args) {
        const handle = await open(path, "r");
        const magic = Buffer.alloc(2);
        try { await handle.read(magic, 0, 2, 0); } finally { await handle.close(); }
        const stream = createReadStream(path);
        await ingest(magic[0] === 0x1f && magic[1] === 0x8b ? stream.pipe(createGunzip()) : stream, basename(path));
      }
    }
    const analysis = builder.finish();
    const response = buildResponse(analysis);
    process.stdout.write(json ? JSON.stringify(response, null, 2) + "\n" : response.text + "\n");
  } catch (error) {
    console.error(error instanceof Error ? error.message : "Could not read log input.");
    process.exitCode = 1;
  }
}

void main();

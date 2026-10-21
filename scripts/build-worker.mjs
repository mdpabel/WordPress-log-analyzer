import { build } from "esbuild";

await build({
  entryPoints: ["src/lib/analyzer.worker.ts"],
  outfile: "public/analyzer-worker.js",
  bundle: true,
  format: "iife",
  platform: "browser",
  target: "es2022",
  minify: true,
});

// Assemble the GitHub Pages site in docs/:
//   docs/index.html      landing page + live demo (from web/)
//   docs/sample.zip      a small archive for the demo (same-origin Range works)
//   docs/remote-zip.mjs  the browser ESM bundle the demo imports
//   docs/api/            typedoc API docs (produced separately by doc:gen)
//
// Run after `npm run build` (for lib/esm) and `npm run doc:gen` (for docs/api).

import { mkdirSync, copyFileSync, cpSync, existsSync } from "node:fs";

mkdirSync("docs", { recursive: true });
cpSync("web", "docs", { recursive: true });
copyFileSync("fixtures/test.zip", "docs/sample.zip");
copyFileSync("lib/esm/index.mjs", "docs/remote-zip.mjs");
if (existsSync("lib/esm/index.mjs.map")) {
  copyFileSync("lib/esm/index.mjs.map", "docs/index.mjs.map");
}

console.log(
  "site assembled in docs/ (index.html, sample.zip, remote-zip.mjs, api/)",
);

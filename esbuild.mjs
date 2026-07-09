// @ts-check

import * as esbuild from "esbuild";
import { readFileSync, writeFileSync, existsSync } from "node:fs";

/**
 * Emit ESM (`.d.mts`) twins of the `.d.ts` declarations so the package's
 * "import" types condition resolves as ESM. Without this, a nodenext/node16
 * ESM consumer sees the types as CommonJS (attw "FalseCJS" masquerade). The
 * `.d.ts` files stay for the "require" condition.
 */
function emitEsmTypes(dir = "lib/types") {
  if (!existsSync(`${dir}/index.d.ts`)) return;
  const withEsmExtensions = (source) =>
    source.replace(/(from\s+["'])\.\/(zip|crypto)(["'])/g, "$1./$2.mjs$3");
  // Relative references from .d.mts files need explicit ESM extensions under
  // node16/nodenext resolution, and every referenced declaration needs a twin.
  const index = withEsmExtensions(readFileSync(`${dir}/index.d.ts`, "utf8"));
  writeFileSync(`${dir}/index.d.mts`, index);
  writeFileSync(`${dir}/zip.d.mts`, withEsmExtensions(readFileSync(`${dir}/zip.d.ts`, "utf8")));
  writeFileSync(
    `${dir}/crypto.d.mts`,
    withEsmExtensions(readFileSync(`${dir}/crypto.d.ts`, "utf8")),
  );
}

/** Options shared by both output formats. */
const shared = {
  entryPoints: ["src/index.ts"],
  bundle: true,
  sourcemap: true,
  minify: true,
};

/** @type {import("esbuild").BuildOptions} */
const esmOptions = {
  ...shared,
  outdir: "lib/esm",
  format: "esm",
  splitting: true,
  target: ["esnext"],
  // Emit .mjs so the bundle is unambiguously ESM regardless of the package
  // "type" field; the cjs build keeps .js (the package default is CommonJS).
  outExtension: { ".js": ".mjs" },
};

/** @type {import("esbuild").BuildOptions} */
const cjsOptions = {
  ...shared,
  outdir: "lib/cjs",
  format: "cjs",
  platform: "node",
  target: ["node22"],
};

const watch = process.env["WATCH"] === "1";

try {
  if (watch) {
    const contexts = await Promise.all([esbuild.context(esmOptions), esbuild.context(cjsOptions)]);
    await Promise.all(contexts.map((ctx) => ctx.watch()));
    console.log("esbuild is watching...");
  } else {
    // Await BOTH builds before exiting. The previous version fired the builds
    // without awaiting and called process.exit(0) immediately, so lib/cjs was
    // frequently never written.
    await Promise.all([esbuild.build(esmOptions), esbuild.build(cjsOptions)]);
    emitEsmTypes();
    console.log("esbuild: esm + cjs build complete");
  }
} catch (err) {
  console.error(err);
  process.exit(1);
}

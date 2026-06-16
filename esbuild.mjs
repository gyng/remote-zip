// @ts-check

import * as esbuild from "esbuild";

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
  target: ["node20"],
};

const watch = process.env["WATCH"] === "1";

try {
  if (watch) {
    const contexts = await Promise.all([
      esbuild.context(esmOptions),
      esbuild.context(cjsOptions),
    ]);
    await Promise.all(contexts.map((ctx) => ctx.watch()));
    console.log("esbuild is watching...");
  } else {
    // Await BOTH builds before exiting. The previous version fired the builds
    // without awaiting and called process.exit(0) immediately, so lib/cjs was
    // frequently never written.
    await Promise.all([esbuild.build(esmOptions), esbuild.build(cjsOptions)]);
    console.log("esbuild: esm + cjs build complete");
  }
} catch (err) {
  console.error(err);
  process.exit(1);
}

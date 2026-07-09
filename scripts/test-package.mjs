import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const temp = mkdtempSync(join(tmpdir(), "remote-zip-consumer-"));

try {
  const packageDir = join(temp, "node_modules", "@gyng", "remote-zip");
  mkdirSync(join(temp, "node_modules", "@gyng"), { recursive: true });
  symlinkSync(root, packageDir, "dir");
  writeFileSync(join(temp, "package.json"), JSON.stringify({ private: true, type: "module" }));
  writeFileSync(
    join(temp, "tsconfig.json"),
    JSON.stringify({
      compilerOptions: {
        module: "NodeNext",
        moduleResolution: "NodeNext",
        noEmit: true,
        strict: true,
        skipLibCheck: false,
      },
      files: ["consumer.ts"],
    }),
  );
  writeFileSync(
    join(temp, "consumer.ts"),
    'import { RemoteZipPointer, crc32 } from "@gyng/remote-zip";\n' +
      "void RemoteZipPointer;\n" +
      "const checksum: number = crc32(new Uint8Array());\n" +
      "void checksum;\n",
  );
  execFileSync(process.execPath, [join(root, "node_modules", "typescript", "bin", "tsc")], {
    cwd: temp,
    stdio: "inherit",
  });
} finally {
  rmSync(temp, { recursive: true, force: true });
}

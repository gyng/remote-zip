import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["src/**/*.test.ts"],
    coverage: {
      provider: "v8",
      include: ["src/**/*.ts"],
      exclude: ["src/**/*.test.ts"],
      reporter: ["text", "html"],
      // Gate in CI (`npm run test:coverage`). Set below current levels so the
      // gate catches regressions without being brittle on small fluctuations.
      thresholds: {
        statements: 90,
        branches: 72,
        functions: 95,
        lines: 90,
      },
    },
  },
});

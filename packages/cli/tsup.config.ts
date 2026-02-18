import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/cli.ts"],
  format: ["cjs"],
  dts: true,
  splitting: false,
  sourcemap: true,
  clean: true,
  treeshake: true,
  minify: false,
  banner: {
    js: "#!/usr/bin/env node",
  },
  external: ["@aegis-sdk/core", "@aegis-sdk/testing"],
});

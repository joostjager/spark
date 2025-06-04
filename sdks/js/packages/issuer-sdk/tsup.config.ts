import { defineConfig } from "tsup";

export default defineConfig({
  entry: [
    "src/index.ts",
    "src/types.ts",
    "src/proto/spark.ts",
    "src/proto/lrc20.ts"
  ],
  format: ["cjs", "esm"],
  dts: true,
  clean: true,
  inject: ['./buffer.js'],
});

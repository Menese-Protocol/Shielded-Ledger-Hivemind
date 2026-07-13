import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import wasm from "vite-plugin-wasm";
import topLevelAwait from "vite-plugin-top-level-await";

export default defineConfig({
  plugins: [react(), wasm(), topLevelAwait()],
  // @dfinity/vetkeys' browser bundle still references Node's `global` alias in development.
  // Keep the alias scoped to the browser global; no Node APIs are exposed.
  define: { global: "globalThis" },
  server: { port: 5178, strictPort: true },
  preview: { port: 5178, strictPort: true },
  optimizeDeps: { exclude: ["./src/prover-pkg/pool_prover_wasm.js"] },
});

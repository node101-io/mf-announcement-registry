import { defineConfig } from "vite";

// Proving uses threads, which need cross-origin isolation (see public/_headers).
const isolation = { "Cross-Origin-Opener-Policy": "same-origin", "Cross-Origin-Embedder-Policy": "require-corp" };

export default defineConfig({
  build: { target: "esnext", chunkSizeWarningLimit: 5000, rollupOptions: { input: { prove: "prove.html" } } },
  optimizeDeps: { exclude: ["@aztec/bb.js", "@noir-lang/noirc_abi", "@noir-lang/acvm_js"]},
  server: { headers: isolation },
  preview: { headers: isolation },
});

import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

// The core serves the console from its binary: the build goes to
// internal/webui/dist, which `go build -tags embedui` embeds.
// During development the core serves a self-signed certificate (`task run`),
// so the proxy does not verify it.
const core = { target: "https://127.0.0.1:8443", secure: false };

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "../internal/webui/dist",
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    strictPort: true,
    // During development, API and login calls go to a core started with `task run`.
    proxy: {
      "/api": core,
      "/auth": core,
    },
  },
  test: {
    environment: "jsdom",
    include: ["src/**/*.test.{ts,tsx}"],
  },
});

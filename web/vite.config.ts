import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

// The core serves the console from its binary: the build goes to
// internal/webui/dist, which `go build -tags embedui` embeds.
const core = "http://127.0.0.1:8080";

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
      "/healthz": core,
    },
  },
  test: {
    environment: "jsdom",
    include: ["src/**/*.test.{ts,tsx}"],
  },
});

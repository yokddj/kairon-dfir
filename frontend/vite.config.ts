import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Default API base when no VITE_API_BASE_URL is set.  Using a
// relative path keeps the frontend and backend under the same
// origin (the Vite dev server) and avoids CORS preflight noise.
const DEFAULT_API_BASE = "/api";

export default defineConfig({
  plugins: [react()],
  server: {
    host: "0.0.0.0",
    port: 5173,
    // Proxy /api/* to the backend so the browser sees a same-origin
    // request and does not need a CORS preflight.  This is the
    // single source of truth for the frontend → backend connectivity.
    proxy: {
      "/api": {
        target: process.env.VITE_API_PROXY_TARGET || "http://localhost:8000",
        changeOrigin: true,
        secure: false,
        ws: false,
      },
    },
    fs: {
      allow: [".."],
    },
  },
  test: {
    include: ["src/**/*.test.{ts,tsx}"],
    environment: "jsdom",
    setupFiles: "./src/test/setup.ts",
    globals: true,
  },
});

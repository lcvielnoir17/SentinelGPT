import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// Dev server proxies API calls to the FastAPI backend so the SPA can talk to
// /api/v1 same-origin during local development outside Docker (Chapter 5).
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: "http://localhost:8000",
        changeOrigin: true,
      },
    },
  },
});

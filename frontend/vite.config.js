// Vite config for the dev preview only.
// This is NOT Sagar's production dashboard config — it exists solely to let
// Jayshree visually verify HopMap.jsx renders correctly before handoff.
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    // Proxy /geo-preview requests to the FastAPI backend so the browser
    // doesn't hit a CORS error when fetching from a different port.
    proxy: {
      "/geo-preview": {
        target: "http://localhost:8002",
        changeOrigin: true,
      },
    },
  },
});

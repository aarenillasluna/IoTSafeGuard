import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Vite proxy: /api → backend uvicorn en 127.0.0.1:8000
// WS: /api/audits/{id}/stream también va via proxy (ws=true).
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    strictPort: true,
    host: "127.0.0.1",
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8000",
        changeOrigin: false,
        ws: true,
      },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: true,
  },
});

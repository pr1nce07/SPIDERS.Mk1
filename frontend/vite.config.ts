import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    host: "127.0.0.1",
    // Let Windows choose an available port (avoids EACCES on reserved ports such as 5173).
    port: 0,
    strictPort: false,
    proxy: {
      "/api": "http://127.0.0.1:8600",
      "/ws": { target: "ws://127.0.0.1:8600", ws: true },
    },
  },
  preview: {
    host: "127.0.0.1",
    port: 0,
    strictPort: false,
  },
  build: { chunkSizeWarningLimit: 2500 },
});

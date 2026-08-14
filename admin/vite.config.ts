import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// The source remains an independent workspace, while the production artifact
// is mounted at /workspace inside Netra's one Vercel project. Locally it keeps
// its own port so both applications can still run side by side.
export default defineConfig({
  base: "/workspace/",
  plugins: [react(), tailwindcss()],
  server: {
    port: 5180,
    strictPort: true,
  },
  preview: {
    port: 5180,
    strictPort: true,
  },
});

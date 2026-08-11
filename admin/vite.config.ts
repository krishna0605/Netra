import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// The admin console is deliberately a separate origin from the investigator
// console. Locally that means its own port; in a deployment it would be its own
// project entirely. 5173 belongs to frontend/, so this one takes 5180.
export default defineConfig({
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

import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: {
    manifest: true,
    chunkSizeWarningLimit: 360,
    rolldownOptions: {
      output: {
        codeSplitting: {
          minSize: 8_000,
          maxSize: 300_000,
          groups: [{
            name: "vendor",
            test: /node_modules[\\/]/,
            entriesAware: true,
            minSize: 8_000,
            maxSize: 300_000,
          }],
        },
      },
    },
  },
})

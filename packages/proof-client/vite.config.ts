import { defineConfig } from "vite";
import react from "@vitejs/plugin-react-swc";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: parseInt(process.env.VITE_PORT || "3000", 10),
  },
  build: {
    target: "es2022",
  },
  base: "/",
});

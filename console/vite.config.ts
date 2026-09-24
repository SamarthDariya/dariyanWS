import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The console is served from its own origin in development and proxies the API, so the session
// cookie is same-site and SameSite=Strict keeps working. Serving the API from somewhere else
// would mean the cookie is never sent and every request looks unauthenticated — which is the
// failure decision 12 warns about, arriving through a dev-server setting rather than a flag.
export default defineConfig({
  plugins: [react()],
  server: {
    // Bound explicitly to IPv4. Vite's default resolves "localhost" to ::1 on this machine, so
    // the dev server listened on [::1]:5173 and nothing on 127.0.0.1 — which presents as the
    // console being unreachable from any script that spells out the loopback address.
    host: "127.0.0.1",
    port: 5173,
    proxy: {
      "/2026-09-01": { target: "http://127.0.0.1:8080", changeOrigin: false },
    },
  },
});

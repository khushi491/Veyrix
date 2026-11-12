import path from "node:path";
import type { NextConfig } from "next";

// Vercel sets VERCEL=1. A hosted build always stays in demo mode so /api cannot
// be rewritten to FastAPI or any development-mode route.
const demoMode =
  process.env.NEXT_PUBLIC_VEYRIX_DEMO === "true" || process.env.VERCEL === "1";

const config: NextConfig = {
  turbopack: { root: path.resolve(process.cwd()) },
  env: {
    NEXT_PUBLIC_VEYRIX_DEMO: demoMode ? "true" : "false",
  },
  async rewrites() {
    if (demoMode) return [];
    return [
      {
        source: "/api/:path*",
        destination: "http://127.0.0.1:8000/api/:path*",
      },
    ];
  },
};
export default config;

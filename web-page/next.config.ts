import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  /* ─── Static export for nginx serving ─── */
  output: "export",
  /* ─── Webpack: exclude GSAP from server bundles to speed up compilation ─── */
  webpack: (config, { isServer }) => {
    if (isServer) {
      config.externals = config.externals || [];
      config.externals.push("gsap");
    }
    return config;
  },
};

export default nextConfig;

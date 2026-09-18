import type { NextConfig } from "next";
import { ROUTED_ASSET_PREFIX } from "./lib/security-headers";

const nextConfig: NextConfig = {
  assetPrefix: ROUTED_ASSET_PREFIX,
};

export default nextConfig;

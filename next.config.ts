import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  webpack: (config: any) => {
    config.resolve.fallback = { 
      ...config.resolve.fallback, 
      fs: false, 
      buffer: require.resolve("buffer"),
      crypto: require.resolve("crypto-browserify"),
      stream: require.resolve("stream-browserify"),
      util: require.resolve("util")
    };
    return config;
  },
  serverExternalPackages: ['@solana/web3.js']
};

export default nextConfig;

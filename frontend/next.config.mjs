/** @type {import('next').NextConfig} */
const nextConfig = {
  eslint: {
    ignoreDuringBuilds: true,
  },
  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: "http://localhost:8001/api/:path*",
      },
      {
        source: "/ws/:path*",
        destination: "http://localhost:8001/ws/:path*",
      },
    ];
  },
};

export default nextConfig;

import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        background: "#000000",
        foreground: "#ffffff",
        cyber: {
          blue: "#0052FF",
          dark1: "#030303",
          dark2: "#050505",
          dark3: "#111111",
          border: "#151515",
          border2: "#1A1A1A",
          textMuted: "#555555",
          textLight: "#777777",
          textLighter: "#888888",
        }
      },
      animation: {
        'marquee': 'marquee 30s linear infinite',
        'fade-in': 'fadeIn 1s ease-out forwards',
        'spin-slow': 'spin 30s linear infinite',
        'spin-slow-reverse': 'spin 30s linear infinite reverse',
      },
      keyframes: {
        marquee: {
          '0%': { transform: 'translateX(0)' },
          '100%': { transform: 'translateX(-50%)' },
        },
        fadeIn: {
          '0%': { opacity: '0', transform: 'translateY(10px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        }
      }
    },
  },
  plugins: [],
};
export default config;

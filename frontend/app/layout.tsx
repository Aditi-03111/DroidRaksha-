import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import "./globals.css";

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-inter",
  display: "swap",
});

const jetbrains = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-mono",
  display: "swap",
});

export const metadata: Metadata = {
  title: "DroidRaksha — India's APK Threat Intelligence Platform",
  description:
    "AI-powered Android APK security analysis platform for detecting malware, banking trojans, UPI fraud apps, and India-specific mobile threats.",
  keywords: [
    "APK analysis",
    "Android malware",
    "India cybersecurity",
    "UPI fraud",
    "mobile threat intelligence",
    "DroidRaksha",
  ],
  openGraph: {
    title: "DroidRaksha — APK Threat Intelligence",
    description: "Scan Android APKs for malware, banking trojans & India-specific mobile threats.",
    type: "website",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className={`${inter.variable} ${jetbrains.variable} dark`}>
      <body className="min-h-screen bg-[#080b12] text-slate-100 antialiased font-sans">
        {children}
      </body>
    </html>
  );
}

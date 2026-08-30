import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "Backtrace — Agent flight recorder",
  description: "Turn raw coding-agent logs into timelines, diagnostics, and restart briefs. Local-first and powered by Python.",
  icons: {
    icon: "/favicon.svg",
    shortcut: "/favicon.svg",
  },
  openGraph: {
    title: "Backtrace — See where your agent changed course",
    description: "A local-first flight recorder for AI coding agents.",
    type: "website",
    images: ["https://raw.githubusercontent.com/vishnugamini/agent-backtrace/main/public/og.png"],
  },
  twitter: {
    card: "summary_large_image",
    title: "Backtrace — See where your agent changed course",
    description: "A local-first flight recorder for AI coding agents.",
    images: ["https://raw.githubusercontent.com/vishnugamini/agent-backtrace/main/public/og.png"],
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased`}
      >
        {children}
      </body>
    </html>
  );
}

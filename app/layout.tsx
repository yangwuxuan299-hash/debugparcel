import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "DebugParcel — Private debug bundles",
  description: "Sanitize HAR files, console logs, and screenshots locally before sharing a web bug report.",
  icons: {
    icon: "/favicon.svg",
    shortcut: "/favicon.svg",
  },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}

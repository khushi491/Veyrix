import type { Metadata } from "next";
import "./globals.css";
export const metadata: Metadata = {
  title: "Veyrix — Agent security",
  description: "Security for Autonomous Intelligence.",
};
export default function Layout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}

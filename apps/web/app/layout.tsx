import type { Metadata } from "next";
import { DemoBanner } from "./demo-banner";
import { demoMode } from "./demo-mode";
import "./globals.css";
export const metadata: Metadata = {
  title: "Veyrix — Agent security",
  description: "Security for Autonomous Intelligence.",
};
export default function Layout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        {demoMode ? <DemoBanner /> : null}
        {children}
      </body>
    </html>
  );
}

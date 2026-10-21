import type { Metadata } from "next";
import { SiteFooter, SiteHeader } from "@/components/SiteChrome";
import { siteOrigin } from "@/lib/site";
import "./globals.css";

export const metadata: Metadata = {
  metadataBase: siteOrigin ? new URL(siteOrigin) : undefined,
  title: { default: "WordPress Log Analyzer | LogScope", template: "%s | LogScope" },
  description: "Analyze WordPress access and error logs in your browser. Find suspicious requests, PHP fatal errors, top IPs and paths, then inspect the supporting log lines.",
  applicationName: "LogScope",
  robots: { index: true, follow: true },
  openGraph: { type: "website", siteName: "LogScope", title: "WordPress Log Analyzer | LogScope", description: "Investigate WordPress access, security, and error logs with evidence-backed findings.", url: siteOrigin || undefined },
  twitter: { card: "summary", title: "WordPress Log Analyzer | LogScope", description: "Understand suspicious requests, fatal errors, and traffic in WordPress logs." },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body><div className="site"><a className="skip-link" href="#main-content">Skip to content</a><SiteHeader /><main id="main-content">{children}</main><SiteFooter /></div></body></html>;
}

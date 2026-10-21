import type { Metadata } from "next";
import Analyzer from "@/components/Analyzer";
import HomeContent from "@/components/HomeContent";
import { absoluteUrl } from "@/lib/site";

export const metadata: Metadata = {
  title: "WordPress Log Analyzer for Access, Error & Security Logs",
  description: "Analyze WordPress access and error logs from cPanel or your server. Find attack clues, PHP fatal errors, top IPs and paths, and inspect the supporting lines privately in your browser.",
  alternates: { canonical: absoluteUrl("/") },
  openGraph: { title: "WordPress Log Analyzer | LogScope", description: "Find suspicious requests, PHP fatals, and traffic patterns in WordPress logs. Analyze files privately in your browser.", url: absoluteUrl("/") },
};

export default function Home() {
  const appSchema = { "@context": "https://schema.org", "@type": "WebApplication", name: "LogScope", description: "Browser-based WordPress access and error log analyzer with security leads, fatal-error findings, and evidence lines.", applicationCategory: "DeveloperApplication", operatingSystem: "Any", isAccessibleForFree: true, ...(absoluteUrl("/") ? { url: absoluteUrl("/") } : {}) };
  return <><script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(appSchema).replace(/</g, "\\u003c") }} /><Analyzer /><HomeContent /></>;
}

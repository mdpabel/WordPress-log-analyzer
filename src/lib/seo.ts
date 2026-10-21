import type { Metadata } from "next";
import { absoluteUrl } from "./site";

export function pageMetadata(title: string, description: string, path: string): Metadata {
  return {
    title,
    description,
    alternates: { canonical: absoluteUrl(path) },
    openGraph: { type: "website", siteName: "LogScope", title: `${title} | LogScope`, description, url: absoluteUrl(path) },
    twitter: { card: "summary", title: `${title} | LogScope`, description },
  };
}

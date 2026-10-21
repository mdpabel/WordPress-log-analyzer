import type { MetadataRoute } from "next";
import { getPublishedGuides } from "@/lib/guides";
import { absoluteUrl } from "@/lib/site";

export const dynamic = "force-static";

export default function sitemap(): MetadataRoute.Sitemap {
  const guides = getPublishedGuides();
  const paths = ["/", "/about/", "/privacy/", "/terms/", ...(guides.length ? ["/guides/"] : []), ...guides.map(guide => `/guides/${guide.slug}/`)];
  return paths.flatMap(path => {
    const url = absoluteUrl(path);
    return url ? [{ url }] : [];
  });
}

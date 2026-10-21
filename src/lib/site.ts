export const siteName = "LogScope";
const configuredEmail = process.env.CONTACT_EMAIL?.trim();
export const contactEmail = configuredEmail && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(configuredEmail) ? configuredEmail : null;

const configuredUrl = process.env.SITE_URL?.trim();
export const siteOrigin = configuredUrl && /^https?:\/\//i.test(configuredUrl)
  ? new URL(configuredUrl).origin
  : null;

export function absoluteUrl(path: string): string | undefined {
  return siteOrigin ? new URL(path, siteOrigin).toString() : undefined;
}

import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import matter from "gray-matter";

export interface Guide {
  slug: string;
  title: string;
  description: string;
  publishedAt: string;
  updatedAt: string;
  readTime: string;
  body: string;
}

const guideDirectory = path.join(process.cwd(), "content", "guides");
const datePattern = /^\d{4}-\d{2}-\d{2}$/;

export function parseGuide(filename: string, source: string): Guide | null {
  const { data, content } = matter(source);
  if (data.status === "draft") return null;
  if (data.status !== "published") throw new Error(`${filename}: status must be draft or published`);
  const slug = path.basename(filename, ".md");
  if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(slug)) throw new Error(`${filename}: use a lowercase hyphenated filename`);
  for (const field of ["title", "description", "publishedAt", "updatedAt"] as const) {
    if (typeof data[field] !== "string" || !data[field].trim()) throw new Error(`${filename}: missing ${field}`);
  }
  if (!datePattern.test(data.publishedAt) || !datePattern.test(data.updatedAt)) throw new Error(`${filename}: dates must use YYYY-MM-DD strings`);
  if (!content.trim()) throw new Error(`${filename}: published guide has no body`);
  const words = content.match(/\b[\p{L}\p{N}]+\b/gu)?.length ?? 0;
  return {
    slug,
    title: data.title.trim(),
    description: data.description.trim(),
    publishedAt: data.publishedAt,
    updatedAt: data.updatedAt,
    readTime: `${Math.max(1, Math.ceil(words / 220))} min read`,
    body: content.trim(),
  };
}

export function getPublishedGuides(): Guide[] {
  return readdirSync(guideDirectory)
    .filter(filename => filename.endsWith(".md"))
    .map(filename => parseGuide(filename, readFileSync(path.join(guideDirectory, filename), "utf8")))
    .filter((guide): guide is Guide => guide !== null)
    .sort((a, b) => b.publishedAt.localeCompare(a.publishedAt) || a.title.localeCompare(b.title));
}

export function findGuide(slug: string): Guide | undefined {
  return getPublishedGuides().find(guide => guide.slug === slug);
}

import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { findGuide, getPublishedGuides } from "@/lib/guides";
import { pageMetadata } from "@/lib/seo";
import { absoluteUrl } from "@/lib/site";

type Props = { params: Promise<{ slug?: string[] }> };

export const dynamicParams = false;

export function generateStaticParams() {
  return [{ slug: [] }, ...getPublishedGuides().map(guide => ({ slug: [guide.slug] }))];
}

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const { slug } = await params;
  if (!slug?.length) {
    const guides = getPublishedGuides();
    return {
      ...pageMetadata("WordPress Log Guides", "Practical guides to investigating WordPress access, security, and error logs.", "/guides/"),
      ...(guides.length === 0 ? { robots: { index: false, follow: true } } : {}),
    };
  }
  const guide = slug.length === 1 ? findGuide(slug[0]) : undefined;
  if (!guide) return {};
  const url = absoluteUrl(`/guides/${guide.slug}/`);
  return {
    title: guide.title,
    description: guide.description,
    alternates: { canonical: url },
    openGraph: { type: "article", siteName: "LogScope", title: guide.title, description: guide.description, url, publishedTime: guide.publishedAt, modifiedTime: guide.updatedAt },
    twitter: { card: "summary", title: guide.title, description: guide.description },
  };
}

export default async function GuidesPage({ params }: Props) {
  const { slug } = await params;
  if (!slug?.length) {
    const guides = getPublishedGuides();
    return <div className="shell content-page">
      <nav className="breadcrumbs" aria-label="Breadcrumb"><Link href="/">Home</Link><span>/</span><span>Guides</span></nav>
      <span className="eyebrow">WORDPRESS LOG GUIDES</span>
      <h1>Understand the evidence in your logs.</h1>
      <p className="page-lead">Detailed walkthroughs for using access and error logs to investigate WordPress issues.</p>
      {guides.length > 0 ? <div className="guide-index">{guides.map(guide => <article key={guide.slug}><span>{guide.readTime}</span><h2><Link href={`/guides/${guide.slug}/`}>{guide.title}</Link></h2><p>{guide.description}</p><Link className="read-link" href={`/guides/${guide.slug}/`}>Read guide →</Link></article>)}</div> : <p className="guide-empty">Guides are being prepared and reviewed. You can use the analyzer now, and return here for detailed walkthroughs.</p>}
      <div className="page-cta"><h2>Have a log ready?</h2><p>Analyze it in your browser and open the original lines behind each finding.</p><Link href="/#tool">Open the analyzer →</Link></div>
    </div>;
  }
  const guide = slug.length === 1 ? findGuide(slug[0]) : undefined;
  if (!guide) notFound();
  const url = absoluteUrl(`/guides/${guide.slug}/`);
  const schema = {
    "@context": "https://schema.org",
    "@type": "Article",
    headline: guide.title,
    description: guide.description,
    datePublished: guide.publishedAt,
    dateModified: guide.updatedAt,
    publisher: { "@type": "Organization", name: "LogScope" },
    ...(url ? { mainEntityOfPage: url } : {}),
  };
  return <div className="shell content-page guide-page">
    <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(schema).replace(/</g, "\\u003c") }} />
    <nav className="breadcrumbs" aria-label="Breadcrumb"><Link href="/">Home</Link><span>/</span><Link href="/guides/">Guides</Link><span>/</span><span>{guide.title}</span></nav>
    <span className="eyebrow">WORDPRESS LOG GUIDE</span>
    <h1>{guide.title}</h1>
    <p className="page-lead">{guide.description}</p>
    <p className="updated">Published <time dateTime={guide.publishedAt}>{guide.publishedAt}</time> · Updated <time dateTime={guide.updatedAt}>{guide.updatedAt}</time> · {guide.readTime}</p>
    <article className="prose guide-body"><ReactMarkdown remarkPlugins={[remarkGfm]}>{guide.body}</ReactMarkdown><div className="page-cta"><h2>Check your own logs</h2><p>Use LogScope to see the relevant counts, findings, and supporting lines.</p><Link href="/#tool">Analyze a log →</Link></div></article>
    <div className="back-guides"><Link href="/guides/">← All guides</Link></div>
  </div>;
}

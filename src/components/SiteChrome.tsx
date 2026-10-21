import Link from "next/link";
import { contactEmail } from "@/lib/site";

export function SiteHeader() {
  return <header className="site-header"><div className="shell header-inner"><Link className="brand" href="/" aria-label="LogScope home"><span className="brand-mark">L</span><span>LogScope<small>WordPress log analyzer</small></span></Link><nav className="site-nav" aria-label="Main navigation"><Link href="/#tool">Analyze logs</Link><Link href="/guides/">Guides</Link><Link href="/about/">About</Link></nav></div></header>;
}

export function SiteFooter() {
  return <footer className="site-footer"><div className="shell footer-grid"><div><Link className="footer-brand" href="/">LogScope</Link><p>Understand WordPress access and error logs, with the evidence behind each finding.</p></div><nav aria-label="Footer navigation"><strong>Explore</strong><Link href="/#tool">Analyze logs</Link><Link href="/#how-it-works">How it works</Link><Link href="/guides/">Guides</Link><Link href="/about/">About</Link></nav><nav aria-label="Legal navigation"><strong>Site information</strong><Link href="/privacy/">Privacy policy</Link><Link href="/terms/">Terms and conditions</Link>{contactEmail && <a href={`mailto:${contactEmail}`}>Contact</a>}</nav></div><div className="shell footer-bottom"><span>© {new Date().getFullYear()} LogScope</span><span>Log findings are investigative leads, not proof of compromise.</span></div></footer>;
}

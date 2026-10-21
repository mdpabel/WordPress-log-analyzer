# LogScope

LogScope is a browser-based analyzer for WordPress and hosting logs. Add access and error logs from cPanel, a VPS, or another host to review traffic, suspicious requests, HTTP failures, and PHP or WordPress errors. Findings include supporting log lines and practical follow-up checks.

LogScope analyzes the files you select locally in your browser. It does not upload log contents to an analysis server or save them to an account.

## Run locally

Install dependencies and start the development server:

```powershell
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000). Select one or more log files, paste a small excerpt, or choose **Try with sample logs**. Add access and error logs together when you need to compare requests with application failures.

## What it analyzes

- Apache and NGINX common or combined access logs, including virtual-host variants
- WordPress and PHP debug logs, Apache error logs, and NGINX error logs
- Plain-text files with any name, including cPanel's extensionless `error_log`
- Gzip-compressed logs, detected from file contents rather than the filename
- Traffic totals and top source IPs, requested paths, user agents, and HTTP status codes
- Security signals such as login or XML-RPC bursts, sensitive-file probes, suspicious requests, PHP requests in uploads, and broad 404 scans
- HTTP 5xx responses and grouped PHP fatal errors, with links to the original evidence

Use the filters to inspect records by IP, path, time, request type, or status. Reports can be downloaded as PDF or text, and filtered log lines can be exported as CSV.

## Analyze logs from the command line

The same analysis engine is available without opening the website:

```powershell
npm run analyze -- access.log debug.log
npm run analyze -- --timezone +06:00 archived-access.gz error_log
npm run analyze -- --json access.log
npm run analyze -- tests/fixtures/error_log
```

The command reads gzip by its file contents. With no file arguments, it reads pasted log text from standard input:

```powershell
Get-Content access.log | npm run analyze
```

Use `npm run analyze -- --help` to see the available options. The optional timezone offset applies to error records that do not include a timezone.

## Build and deploy

The project exports a static website to `out/`:

```powershell
npm run build
```

For a public deployment, set `SITE_URL` to the site's canonical HTTPS origin before building. This adds canonical URLs and populates `sitemap.xml` and `robots.txt`. `CONTACT_EMAIL` is optional and adds a contact link to the site.

```powershell
$env:SITE_URL="https://your-domain.example"
$env:CONTACT_EMAIL="hello@your-domain.example"
npm run build
```

Replace the examples with your actual domain and contact address. Deploy the contents of `out/` to static hosting that serves directory index pages over HTTPS. Without `SITE_URL`, the site can still be built for local preview, but the sitemap has no absolute URLs.

## Add a guide

Guides are Markdown files in [`content/guides/`](content/guides/). Copy [`example-guide.md`](content/guides/example-guide.md), write the front matter and article, then keep `status: draft` while it is being reviewed. Drafts do not create public pages or appear in the guide list or sitemap.

After the article is ready, change its status to `published` and run `npm run build`. The filename becomes the URL slug. See [`content/README.md`](content/README.md) for required fields, formatting, and the publishing checklist.

## Privacy and interpretation

Analysis runs in a browser Web Worker. The browser accepts files up to 512 MB each and gzip files up to 1 GB after expansion. Common secret-like URL parameters and headers are redacted in displayed and exported lines, but custom formats may contain values the redactor does not recognize. Review reports before sharing them.

Supported formats are not exhaustive. The import quality panel shows unrecognized lines and examples. For very large logs, summary counts scan all parsed records, while detailed findings and searchable evidence retain the first 100,000 and last 20,000 records. An incident in the middle may not appear in findings or filtered exports.

An access log records requests and server responses; by itself, it cannot prove a successful login, code execution, or malware installation. A PHP stack path is a lead to investigate, not proof that the named plugin or theme caused the error. Compare findings with WordPress activity, WAF events, file changes, and the original logs before taking action.

## Project commands

```powershell
npm run dev        # Start the development server
npm run build      # Export the static site to out/
npm run analyze    # Analyze logs from the command line
npm run typecheck  # Check TypeScript types
npm test           # Run the project test suite
```

# WordPress Log Analyzer — product and build plan

Research date: 2026-10-21. This plan assumes a standalone web app for site owners, agencies, and hosting support teams. It starts with files and pasted logs; a WordPress plugin or server connection is optional later.

## Product promise

Turn raw WordPress and hosting logs into a short, trustworthy answer to: **What happened, when did it start, what was affected, and what should I inspect next?** The product covers access traffic, attacks and abuse, errors, performance, and WordPress/WooCommerce application events. Each finding must link back to the exact source lines and offer concrete next checks. The app should never claim that a login succeeded, a site was compromised, or a plugin caused an outage when the supplied logs do not establish that.

## Current build priority

The current milestone is the analysis tool itself: paste or select logs, parse them, and return a clear response with traffic facts, security findings, error explanations, evidence, and next checks. Keep the web interface simple while improving format coverage, detection accuracy, and report quality. The same engine is available through the browser and the `npm run analyze` command. Visual redesign, accounts, hosting integrations, and large-scale cloud processing follow after the core results are validated with real logs.

## Full product scope

| Area | Questions the tool should answer | Main evidence |
| --- | --- | --- |
| Access and traffic | Who/what requested which pages? When did traffic change? Which paths, IPs, hosts, bots, status codes, and referrers dominate? | Apache/NGINX/LiteSpeed access logs; CDN logs. |
| Security and attacks | Are there login bursts, XML-RPC abuse, scanners, exploit probes, sensitive-file requests, enumeration, or WAF blocks? What was targeted and was it blocked? | Access logs plus ModSecurity, Cloudflare, Wordfence, or other WAF/audit logs when supplied. |
| Errors and root-cause leads | Which fatal errors, warnings, upstream failures, and database problems appeared? What component and request coincide with them? | WordPress debug, PHP, web-server error, WooCommerce, and access logs. |
| Performance and availability | Which paths are slow, error-prone, or consuming bandwidth? Did a traffic surge coincide with an outage? | Access logs with timing when available, web-server/PHP-FPM errors, optional monitoring data. |
| WordPress operations | Are cron, REST API, admin-ajax, WooCommerce checkout/webhooks, plugins, or themes involved? | URL patterns, application logs, WooCommerce logs, optional activity events. |

Coverage is input-dependent: one access log can reveal request patterns and status codes, while a credible explanation of a fatal error needs an error log. A generic access log cannot show a request body, a confirmed successful WordPress login, or server-side execution of a payload. The report should say which additional log would answer an unresolved question. [OWASP logging guidance](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) also distinguishes application events from web-server records.

## Market review

| Tool | What it already does well | Opening for this product |
| --- | --- | --- |
| [GoAccess](https://goaccess.io/features) | Fast web access-log statistics, many formats, real-time HTML/terminal reports, exports. | WordPress-specific incident explanations and correlation with PHP, WordPress, and WooCommerce errors. |
| [cPanel AWStats](https://docs.cpanel.net/cpanel/metrics/awstats/) | Traffic, HTTP status, browser, and referral reports inside hosting. | Portable, cross-host diagnosis from several log types and actionable evidence. |
| [Wordfence Live Traffic](https://www.wordfence.com/help/tools/live-traffic/) and [Audit Log](https://www.wordfence.com/help/audit-log/) | Recent traffic/security events and WordPress actions on an instrumented site. | Offline analysis of exported hosting logs, including when wp-admin is unavailable or the plugin was never installed. |
| [Query Monitor](https://wordpress.org/plugins/query-monitor/) | Deep in-request PHP, database, and HTTP debugging for developers. | Historical incident analysis without reproducing the issue on a live site. |
| [WordPress error-log viewers](https://wordpress.org/plugins/error-log-viewer/) and [WooCommerce Logs](https://woocommerce.com/document/understanding-the-woocommerce-system-status-report/) | View and search application errors in wp-admin. | Combine errors with access-log timing and traffic to explain scope and likely next checks. |
| [Better Stack](https://betterstack.com/log-management/) | Large-scale ingestion, search, alerts, dashboards, and observability. | A simple WordPress-specific workflow that works from one exported `.gz` file or pasted excerpt. |

**Positioning:** a comprehensive WordPress log investigation tool with traffic analytics, security triage, and error diagnosis in one workflow. This is a product hypothesis to validate with users, not a claim that competitors cannot perform these analyses with configuration.

## Input and evidence model

1. **Initial input:** paste text, `.log`/`.txt`, and cPanel `.gz` raw access exports. Support multiple files in one analysis, with a user-supplied site name and timezone when needed. cPanel documents `.gz` downloads for Apache and NGINX raw access logs: [Raw Access](https://docs.cpanel.net/cpanel/metrics/raw-access/).
2. **First parsers:** Apache common/combined and virtual-host variants; NGINX common/combined; WordPress `wp-content/debug.log`; common Apache/NGINX/PHP-FPM error formats. WordPress documents `WP_DEBUG_LOG` and `debug.log`: [Debugging in WordPress](https://developer.wordpress.org/advanced-administration/debug/debug-wordpress/). Apache documents common/combined fields and error logs: [Apache log files](https://httpd.apache.org/docs/current/logs.html).
3. **Next parsers:** WooCommerce logs, ModSecurity audit events, Cloudflare JSON logs, LiteSpeed variants, custom NGINX formats, JSON lines, and optional Wordfence/activity exports. WooCommerce describes its logs and automatic `fatal-errors` source: [WooCommerce System Status](https://woocommerce.com/document/understanding-the-woocommerce-system-status-report/). cPanel documents its [ModSecurity audit log](https://docs.cpanel.net/knowledge-base/cpanel-product/the-cpanel-log-files/). Cloudflare Logpush is a delivery mechanism, not storage/search: [Logpush](https://developers.cloudflare.com/logs/logpush/).
4. **Normalized event:** timestamp in UTC plus original timezone, source file and line number, log type, host, IP, HTTP method, path, query (redacted by default), status, bytes, response duration if present, user agent, severity, message, and extracted WordPress component. Keep the original line accessible only in the private analysis session.
5. **Parse report:** detected format, confidence, first/last timestamp, parsed/skipped counts, example failed lines, duplicate count, and field availability. Ask for a format choice if auto-detection is weak; never silently invent missing fields.

## First version: guided incident triage

### User journey

1. Pick a task: **Traffic overview**, **Attacks and abuse**, **Errors and why they happened**, **Performance / site down**, **404s / broken paths**, or **Explore all logs**.
2. Drop one or more files or paste a log excerpt. Show host-specific instructions for finding logs in cPanel, VPS Apache/NGINX, WordPress, and WooCommerce.
3. Preview detected formats, coverage period, timezone, parser quality, and privacy controls before analysis.
4. Show an overview with traffic and status-code trends, security findings, error clusters, performance signals, time window, confidence, supporting counts, and links to filtered evidence. Let users switch to dedicated Access, Security, Errors, and Performance views.
5. Let users filter by time, status, IP, URL/path, method, user agent, component, severity, and source file; search raw text within the analysis.
6. Export a redacted HTML/PDF summary and filtered CSV/JSON records, including the caveat and evidence behind each finding.

### Access analysis and exploration

Show requests over time, status-code mix, bandwidth, unique IPs, top paths, referrers, user agents, hosts, and methods. Group query variants into canonical paths while retaining original request evidence. Provide drill-down from every chart to matching lines. Include per-IP and per-path timelines, peak-minute comparison, and filters for known bots versus unknown automation; never treat a user-agent string as proof of bot identity.

### Security analysis and attack detection

| Detection | What to show | Evidence limit |
| --- | --- | --- |
| Login and XML-RPC pressure | Attempts/rates over time, targeting IPs, distributed patterns, response-code mix. | Label as login requests or likely password attacks; confirm outcomes only with auth/audit events. |
| Reconnaissance and enumeration | High 404 churn, `wp-json`/author probing, plugin/theme path enumeration, unusual method patterns. | Some requests may be legitimate crawlers or monitoring. |
| Exploit probes | Path traversal, injection-shaped query strings, suspicious upload/execution paths, known sensitive-file requests. | A matching payload is an attempted probe, not proof of exploitation. |
| WAF outcomes | Rules triggered, blocked versus allowed events, rule IDs, false-positive candidates and affected legitimate paths. | Only available when WAF logs are supplied; a 403 alone does not identify a WAF rule. |
| Possible post-probe activity | A probe followed by unusual requests, uploads, or 2xx responses to executable paths from related IPs. | Escalate for manual investigation; access status alone cannot confirm compromise. |
| Resource abuse | High request rates, excessive bandwidth, costly WordPress endpoints, hotlinking patterns. | Distinguish traffic volume from malicious intent. |

For each finding show severity, count, first/last seen, targeted paths, source IPs, response outcomes, example requests, why the rule fired, and practical follow-up. Suggested actions can include checking Wordfence/WAF audit events, confirming whether XML-RPC is needed, reviewing rate limits, or inspecting files and authentication records. Do not automatically block an IP or disable a WordPress feature. [Wordfence documents login and XML-RPC brute-force protection](https://www.wordfence.com/help/firewall/brute-force/); [cPanel documents separate ModSecurity logs](https://docs.cpanel.net/knowledge-base/cpanel-product/the-cpanel-log-files/).

### Error diagnosis and next steps

Group errors by normalized message and stack trace, count occurrences, find first/last seen, extract referenced file and line, classify component (core, plugin, theme, server), and align them with nearby access failures. An explanation card should show **what the message means**, **likely causes supported by evidence**, **checks to confirm**, and **safe next actions**. Examples:

| Error pattern | Explanation and suggested checks |
| --- | --- |
| `Allowed memory size exhausted` | PHP hit its memory limit. Identify the failing script/plugin from the stack trace, check for a recent update or request surge, and review memory settings and hosting limits. Raising the limit alone may hide a leak. |
| `Call to undefined function` / missing class | Code invoked something unavailable. Check plugin/theme versions, failed deployment, dependency loading, and PHP compatibility using the cited file/line. |
| Uncaught exception or `TypeError` | Identify the first application frame and repeat pattern; inspect recent code/plugin changes and reproduce on staging. |
| Database connection or query failure | Correlate with 5xx windows; inspect database service, credentials/configuration, connection limits, and slow queries as relevant to the exact message. |
| Upstream timeout / gateway error | Compare affected paths and timing with PHP-FPM/NGINX errors, load, and long-running requests. |
| Permission or disk-space error | Show the affected path and operation; inspect permissions, ownership, quota, and available disk space before changing anything. |

Recommendations must be conditional and evidence-based. Show “possible cause” when logs do not establish causality, and point to the missing log or check. [WordPress debugging guidance](https://developer.wordpress.org/advanced-administration/debug/debug-wordpress/) and [Apache error-log guidance](https://httpd.apache.org/docs/current/logs.html) establish the source roles.

### Initial cross-log detectors

| Detector | Evidence and output | Guardrail |
| --- | --- | --- |
| 5xx spike | Rate change, affected paths, first/last occurrence, correlated error messages. | Access logs identify failing requests; a cause needs supporting error evidence. |
| PHP fatal and memory failure | Group repeated stack traces/messages; identify plugin/theme path when present. | A path in a stack trace is a lead, not proof of fault. |
| Login pressure | Bursts against `wp-login.php`, `xmlrpc.php`, and relevant auth routes by IP and time. | An access response alone does not establish login success. |
| Scanning and exploit probes | Repeated requests for missing PHP files, `wp-config.php`, vulnerable paths, injection-shaped URLs, and high 404 rates. | Describe as suspicious requests, not confirmed compromise. |
| Bot/resource pressure | Top IPs and user agents by rate, bytes, and expensive WordPress endpoints (`admin-ajax.php`, `wp-cron.php`, REST routes). | User agents can be spoofed; shared proxy IPs require caution. |
| Slow paths | p95/p99 and outliers where the format includes duration/upstream timing. | If timing is absent, show “unavailable,” not a derived estimate. |
| Broken paths | Frequent 404 URLs grouped by normalized path, with referrers if present. | Keep actual paths for evidence; remove tracking/sensitive query parameters. |

### Extraction presets

Provide one-click views for all 4xx/5xx requests, a selected IP's activity, a selected URL's timeline, login/XML-RPC/admin-ajax/wp-cron requests, injection/traversal probes, sensitive-file requests, WAF blocks, unique 404 paths, PHP fatals/warnings, affected plugins/themes, slowest paths, and traffic around a selected incident minute. Each preset should support CSV/JSON export.

## Trust, privacy, and safety requirements

- Logs can contain IP addresses, account names, URL tokens, email addresses, cookies, and payment or checkout details. Redact known secret parameters and headers before display/export; allow a clearly marked reveal of original lines inside a private session.
- Start with browser-local analysis for pasted text and bounded files if practical, so raw logs do not leave the device. If cloud processing is needed for large files, require an explicit mode choice, encrypt in transit and at rest, isolate tenant jobs, set a short retention period, and expose immediate deletion. Publish exactly which mode is being used.
- Stream parsing and gzip decompression with file-size and expanded-size limits; reject archive bombs and unsupported files. Render every log field as untrusted text, never HTML. Apache explicitly warns that client-supplied log content may include control characters: [Apache log files](https://httpd.apache.org/docs/current/logs.html).
- Do not execute or fetch any URL, script, path, or command found in uploaded logs. Do not expose a direct server/WordPress connection in the first release.
- Mark every generated conclusion as **observed**, **likely**, or **needs more evidence**, with the exact counts, time window, and supporting lines. Any AI explanation is optional and must be grounded in parsed evidence; deterministic detectors produce the finding first.
- Handle proxy/CDN IPs carefully. Do not treat `X-Forwarded-For` as the client IP without a configured trusted proxy chain. Avoid automatic IP blocking or WordPress changes.

## Proposed implementation

**Framework choice:** Next.js (App Router) with React and TypeScript for the web app. Its client components support the interactive analysis workspace, while route handlers can support accounts, saved reports, and upload orchestration later. Keep the parsing and detection engine in a framework-independent TypeScript package rather than inside Next.js pages or request handlers.

**First release:** A streaming parser running in a Web Worker, bounded aggregates, and IndexedDB for local analysis sessions. A shared parser/detector package produces structured events and findings; format adapters are separate modules. This keeps simple uploads fast and private while leaving room for a server worker later. Verify browser memory limits with representative cPanel exports before publishing a file-size promise.

**Scale path:** an API receives explicitly authorized cloud uploads, stores encrypted temporary objects, queues parsing jobs, and stores normalized events in a query-friendly database. Large-file parsing runs in a separate background worker, not in a web request. Add resumable upload and live connectors only after the offline workflow is validated. A WordPress plugin may later collect application events, but must be optional: the product should remain useful while a site is inaccessible.

**Core boundaries:** input reader → format detection → parser → normalized event → deterministic detectors → evidence-backed report → export. Version detector rules and record the rule version in reports so results are reproducible.

## Delivery sequence and release gates

| Phase | Build | Gate |
| --- | --- | --- |
| 0. Discovery | Collect anonymized sample logs from cPanel Apache/NGINX, VPS, WordPress debug, and WooCommerce; interview 8–12 site owners/support staff about real incidents. | Confirm the top three questions and obtain a representative, permitted fixture set. |
| 1. Parser foundation | Paste/file/`.gz`, format detection, timezone handling, parse report, normalized events, fixtures for malformed and mixed logs. | ≥95% of valid lines parse for supported fixture formats; unparsed lines are visible and counted. |
| 2. First useful release | Access dashboard, security view (login/XML-RPC pressure, scans/probes, resource abuse), error diagnosis cards (fatal, memory, timeout), cross-log timeline, filters, evidence, extraction presets, redacted export. | On a review set of traffic, attack, and outage incidents, users can find relevant evidence and understand uncertainty without developer help. |
| 3. Richer diagnosis | WooCommerce and ModSecurity parsers; WAF outcomes; more error patterns; custom formats; saved private sessions. | Compare findings and recommendations against manual expert review; track false positives. |
| 4. Team/scale | Cloud jobs, large files, team sharing, retention controls, optional connectors/alerts. | Security review and load tests before accepting production-scale uploads. |

## Decisions before coding

1. Validate **primary user**: agency/support technician versus nontechnical site owner. This determines report language and pricing.
2. Set first-release **file-size target** after real fixture benchmarks. Browser-local is the default proposal; cloud processing is a deliberate second mode.
3. Choose the first **detector depth** from interviews. Recommendation: ship the access overview, attack investigation, and fatal-error diagnosis together; expand rule coverage and integrations after validating all three.
4. Decide whether the product is hosted SaaS, self-hosted, or both after validating privacy expectations and support needs.

## Immediate next build tasks

1. Create a small, sanitized fixture corpus covering each first-release format and failure mode.
2. Define normalized event and finding schemas, including evidence references and missing-field behavior.
3. Implement the streaming import and format detector with a visible parse-quality screen.
4. Build one end-to-end workflow in each core area: access traffic, attack investigation, and fatal-error diagnosis. Then expand the detector catalog.
5. Run five usability sessions using actual incident questions and revise the report language and filters.

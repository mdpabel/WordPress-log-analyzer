---
status: draft
title: "Check whether LogScope read your WordPress log correctly"
description: "Use the import quality panel to spot unrecognized lines, missing timestamps, and the evidence limits of a large log analysis."
publishedAt: "2026-10-21"
updatedAt: "2026-10-21"
---

Before acting on a finding, check how much of the file LogScope understood. A quiet findings list can mean there were no detected patterns, or that the file used a format the parser did not recognize. The **Import quality and limits** panel helps distinguish those cases.

## Compare lines read with records parsed

Choose a file or paste an excerpt, then select **Analyze logs**. Open **Import quality and limits** below the traffic summary. The panel shows lines read, unrecognized lines, records without a known timezone, and the recorded time span. The top of the report separately shows the number of parsed access and error records.

For example, a standard access line looks like this (the IP is reserved for documentation):

```text
203.0.113.5 - - [21/Oct/2026:10:24:36 +0000] "GET /wp-login.php HTTP/1.1" 200 100 "-" "Mozilla/5.0"
```

LogScope should count this as one access request. Its timestamp includes `+0000`, so it can place the request on a timeline. A `200` means the server returned an HTTP success response; it does not tell you whether a WordPress login succeeded.

If unrecognized lines are greater than zero, open **Show unrecognized line examples**. The panel retains up to five redacted examples, with source filename and line number. Compare them with the original file. A few blank or wrapper lines may be harmless; a large share of unrecognized request lines means the report is incomplete. A custom host format may need a parser change.

## Check timestamps before comparing files

Some PHP error lines do not include a timezone. LogScope leaves those records undated unless you supply an offset under **Server timezone (optional)** before analysis. Use the server's log timezone, which may differ from your computer's. Without a reliable offset, do not claim that an error and an access request happened in the same minute.

The time filters in **Browse log lines** use your device's timezone. Check that interpretation when tracing an incident across logs from different servers.

## Recognize the large-file evidence limit

The browser accepts a file up to 512 MB, including a file named `error_log` without an extension. It detects gzip from the file content and allows up to 1 GB after expansion. For a larger file, use the command-line analyzer or obtain a narrower export.

For very large inputs, LogScope scans every recognized record for summary totals and status counts. It also tracks top IPs, paths, and user agents, though these counts can become lower bounds when there are too many distinct values. The detailed finding and searchable-line view retains the first 100,000 and last 20,000 parsed records. When this limit applies, the report displays **Some findings may be missing**. A request in the omitted middle still contributes to totals but may not appear in a finding, IP trace, filtered view, or CSV export.

If the incident falls in that middle period, export the relevant time window from your server and analyze it separately. Keep the original log so you can verify line numbers and context. A lack of findings in a truncated analysis does not clear the site.

## Next check

Once coverage looks sound, open a finding and inspect its supporting lines. For security questions, compare those lines with WAF, WordPress activity, and file-change evidence. For a fatal error, compare the error message with access requests around the same time. The report provides leads; the original records remain the evidence.

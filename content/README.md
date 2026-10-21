# Guide publishing

Add one Markdown file per guide in `content/guides/`. Its lowercase, hyphenated filename becomes the public slug. For example, `investigate-wordpress-500-errors.md` becomes `/guides/investigate-wordpress-500-errors/`.

Copy `guides/example-guide.md` and keep `status: draft` while writing. Drafts do not generate pages and are absent from the index and sitemap. Change to `status: published` after reviewing the article, then rebuild the site.

Required front matter: `status`, `title`, `description`, `publishedAt`, and `updatedAt`. Quote dates in `YYYY-MM-DD` format. The page creates the H1 and dates from front matter, so start the body with an introduction and use H2 for sections. Standard Markdown links, lists, code blocks, and tables work.

Before publishing, check that the guide answers a specific question, uses an original redacted or synthetic example, accurately describes the current tool, explains what the logs cannot prove, cites primary sources for external claims, and has no placeholders. Update `updatedAt` after substantive revisions.

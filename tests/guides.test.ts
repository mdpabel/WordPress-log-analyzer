import assert from "node:assert/strict";
import test from "node:test";
import { getPublishedGuides, parseGuide } from "../src/lib/guides";

const frontMatter = `---
status: published
title: "A specific title"
description: "A useful description"
publishedAt: "2026-10-21"
updatedAt: "2026-10-21"
---

## First step

Explain the evidence.
`;

test("published Markdown provides route metadata and body", () => {
  const guide = parseGuide("first-step.md", frontMatter);
  assert.equal(guide?.slug, "first-step");
  assert.equal(guide?.title, "A specific title");
  assert.match(guide?.body ?? "", /## First step/);
});

test("drafts are excluded from published guides", () => {
  assert.equal(parseGuide("draft.md", frontMatter.replace("status: published", "status: draft")), null);
  const guides = getPublishedGuides();
  assert.equal(guides.length, 0);
});

test("incomplete published front matter fails the build", () => {
  assert.throws(() => parseGuide("bad.md", frontMatter.replace("description: \"A useful description\"\n", "")), /missing description/);
});

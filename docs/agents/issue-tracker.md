# Issue tracker: GitHub

Issues and specs live in GitHub Issues for Tom-AT-e/js-spc.

Use the connected GitHub tools or the gh CLI. When using gh,
specify --repo Tom-AT-e/js-spc if outside this clone.
For multiline bodies, use --body-file.

## Operations

- Publish a ticket or spec: create a GitHub issue.
- Fetch a ticket: read its title, body, labels, and comments.
- Triage: apply the labels in docs/agents/triage-labels.md.
- Link child tickets using GitHub sub-issues. If unavailable,
  add "Part of #<parent>" to the child and link it in the parent.
- Record blocking relationships using native issue dependencies.
  If unavailable, add "Blocked by: #<number>" to the child.

## Pull requests as a triage surface

**PRs as a request surface: no.**

## Wayfinding

A map is an issue labelled wayfinder:map. Link its child tickets
as sub-issues and label them wayfinder:research,
wayfinder:prototype, wayfinder:grilling, or wayfinder:task.

Choose the first open child in map order with no open blockers
and no assignee. Claim it by assigning yourself. On completion,
comment with the result, close the ticket, and append a result
summary and link to the map's Decisions-so-far.

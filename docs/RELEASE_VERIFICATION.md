# Release verification

Status: implementation GO; source publication ready. Hosted release remains blocked until the remaining browser journeys are recorded.

Required evidence:

- `npm run check`: 22/22 tests passed on 2026-10-17 MYT, including the theme-control accessibility regression test.
- CLI: the valid synthetic fixture returned `preflight-clear`; missing/invalid manifest, MCP, skill metadata, secret, size, and server-boundary probes returned bounded findings.
- Real package check: AI Usage Lens `dist-plugin` (25 files) returned 13 passes, zero warnings, zero blockers, and three informational/manual gates.
- Local HTTP verification: index and allowlisted modules returned 200 with CSP and `nosniff`; `/package.json` and a hostile Host header returned 404.
- Accessibility implementation: semantic headings and landmarks, labeled folder input, live status, visible `:focus-within`, responsive single-column breakpoint, persistent light/dark toggle, and reduced-motion CSS are present. The theme control now exposes its next action without a contradictory pressed state.
- Independent review: final GO after four adversarial rounds. Fixes included complete portable field validation, credential-safe findings, aggregate memory bounds, server route/Host hardening, MCP-only evidence scope, and keyboard focus treatment.
- Browser QA evidence: a new dedicated connected-Chromium tab loaded the loopback app. Desktop light and dark rendering and the theme transition were directly observed. The first valid-folder selection attempt ended with the browser tool error `Transport closed`; it was not retried. Folder processing, export, clear/recovery, mobile layout, keyboard completion, and reduced-motion behavior therefore remain unclaimed.
- Source publication gate: record a signed commit, public personal repository head, and successful exact-commit CI.
- Deployment gate: complete the browser QA above and separately confirm eligible free personal hosting. No hosted deployment is claimed.

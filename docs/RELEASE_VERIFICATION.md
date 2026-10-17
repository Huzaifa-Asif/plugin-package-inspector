# Release verification

Status: implementation, source, and hosted release GO.

Required evidence:

- `npm run check`: 22/22 tests passed on 2026-10-17 MYT, including the theme-control accessibility regression test.
- CLI: the valid synthetic fixture returned `preflight-clear`; missing/invalid manifest, MCP, skill metadata, secret, size, and server-boundary probes returned bounded findings.
- Real package check: AI Usage Lens `dist-plugin` (25 files) returned 13 passes, zero warnings, zero blockers, and three informational/manual gates.
- Local HTTP verification: index and allowlisted modules returned 200 with CSP and `nosniff`; `/package.json` and a hostile Host header returned 404.
- Accessibility implementation: semantic headings and landmarks, labeled folder input, live status, visible `:focus-within`, responsive single-column breakpoint, persistent light/dark toggle, and reduced-motion CSS are present. The theme control now exposes its next action without a contradictory pressed state.
- Independent review: final GO after four adversarial rounds. Fixes included complete portable field validation, credential-safe findings, aggregate memory bounds, server route/Host hardening, MCP-only evidence scope, and keyboard focus treatment.
- Browser QA evidence: a dedicated connected-Chromium tab directly confirmed desktop light/dark rendering and the theme transition. A separate isolated official Playwright Chromium run then passed all four controlled journeys: valid-folder processing and JSON export; clear, invalid-folder, and recovery behavior; keyboard focus and persisted theme state; mobile single-column layout without horizontal overflow; and reduced-motion behavior. The automated run completed 4/4 tests on 2026-10-18 MYT. Chromium is covered; Firefox, WebKit, and a screen-reader session are not claimed.
- Source publication baseline: signed commit `b375e852e01bc2019026e806a6aee968e655f5e2` was verified with the existing Huzaifa Asif Git key, was the exact public `main` head, and passed GitHub Actions on Node 20, 22, and 24. The deployment commit must likewise be signed, pushed, and pass exact-commit CI.
- Hosting eligibility: the repository API confirms `Huzaifa-Asif/plugin-package-inspector` is personal and public. GitHub's current documentation includes Pages for public repositories on GitHub Free and supports static HTML/CSS/JavaScript project sites. This non-commercial, dependency-free static utility fits that boundary.
- Hosted release: GitHub Pages successfully deployed commit `9e67fdd91c7356c039af383d9d02f35cca3cbca2` to `https://huzaifa-asif.github.io/plugin-package-inspector/`. Production checks confirmed HTTPS 200 for the page, `text/javascript` for `src/app.mjs`, the restrictive page-level CSP, project-subpath asset loading, and 4/4 Chromium journeys. Folder inspection produced no post-load network request and no console error. The Pages workflow completed successfully; later documentation-only commits remain subject to the same exact-commit CI and deploy checks.

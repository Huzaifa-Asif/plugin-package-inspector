# Changelog

## Unreleased

- Resolve effective OpenAI settings using documented inline-over-overlay replacement semantics.
- Separate portable manifest validity, OpenAI metadata type checks, listing-readiness guidance, and public-submission eligibility.
- Flag app declarations and lifecycle hooks as current public ZIP submission exclusions, including overlay-only declarations.
- Correct portable required metadata to `$schema` plus `name`; `version` and `description` remain optional.
- Warn when a portable dotted identifier needs a lowercase alphanumeric, single-hyphen name for OpenAI submission.
- Add regression coverage for minimal portable manifests, overlay precedence, exclusion detection, conditional listing gaps, invalid metadata types, and both supported `defaultPrompt` forms.
- Make the theme toggle expose a single, accurate next-action label instead of a contradictory pressed state.
- Add a regression test for the theme control's accessible semantics.
- Add a restrictive page-level Content Security Policy and no-referrer policy for static hosting.
- Disclose GitHub Pages security logging while preserving the local-only package-data boundary.
- Record complete Chromium QA for folder processing, export, clear/recovery, theme persistence, mobile layout, keyboard focus, and reduced motion.
- Publish and verify the personal GitHub Pages demo, including production MIME, CSP, subpath, network-boundary, and full browser-flow checks.

## 0.1.0 — 2026-10-16

- Add a local-only responsive browser inspector and bounded Node CLI.
- Validate portable plugin, MCP, and skill package structure against current published schemas and guidance.
- Add credential-safe findings, privacy/security documents, threat model, and MCP submission-evidence guidance.
- Add 21 initial regression tests covering valid, invalid, adversarial, memory-bound, and local-server cases.
- Record independent implementation GO and keep hosted deployment blocked on actual browser QA.

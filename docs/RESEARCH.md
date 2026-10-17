# Research and scope decision

Checked 2026-10-16 MYT.

## User need

Current plugin submission spans separate official pages for package layout, MCP and skill architecture, authentication, security/privacy, testing, and submission evidence. A publisher must reconcile these before portal upload. A missed root manifest, misplaced skill, credential leak, unsupported auth shape, or incomplete test packet can block review late.

## Existing offerings reviewed

- Official OpenAI packaging and submission documentation is authoritative but is guidance, not a local multi-file preflight app.
- Platform connection testing exercises an installed plugin, but it does not provide a shareable offline package report before upload.
- Public GitHub searches for `plugin package inspector` and `OpenAI plugin validator SKILL.md` returned no direct repository result on 2026-10-16 MYT.
- General MCP directories and security scanners focus on discovery or runtime/server risk, not the combined portable ZIP layout and human submission packet.

## Decision

Build a narrow, original, dependency-free app that inspects an extracted directory locally, emits explainable findings, avoids credential handling, and preserves unknown/manual states. It does not claim policy certification or directory approval.

The published Agent Plugins 1.0 MCP schema currently rejects extra server properties, while OpenAI's packaging guide documents server-level `extensions.com.openai.auth`. The inspector treats the portable schema as the deterministic file-format baseline and reports such an extension as not portable-schema-clean; publishers must reconcile this documented conflict with the current submission portal rather than receiving a false clear.

The portable plugin schema requires `$schema` and `name`; `version` and `description` are optional. OpenAI-specific settings can be inline at `extensions.com.openai` or supplied by `.codex-plugin/plugin.json`, but an inline object replaces the compatibility overlay rather than merging with it. The inspector therefore reports the effective source, validates known interface field types without turning conditional listing guidance into portable-schema failures, and reports common listing gaps separately.

Portable names may contain dots, but OpenAI's submission field reference says packages planned for submission should use lowercase letters, numbers, and single hyphens. The inspector preserves portable validity for a dotted name while emitting a distinct OpenAI submission warning.

OpenAI's current submission guidance excludes packages containing app declarations (`apps` or `.app.json`) or lifecycle hooks from public ZIP submission, even though those features remain supported for local Codex distribution. The inspector reports that eligibility issue separately from portable validity and does not claim portal acceptance.

## Authoritative references

- https://developers.openai.com/plugins/concepts/plugins
- https://developers.openai.com/plugins/build/plugins
- https://developers.openai.com/plugins/build/auth
- https://developers.openai.com/plugins/guides/security-privacy
- https://developers.openai.com/plugins/plugin-guidelines
- https://developers.openai.com/plugins/deploy/connect-chatgpt
- https://developers.openai.com/plugins/deploy/submission
- https://developers.openai.com/plugins/deploy/app-review

## Portfolio and allocation

This is a web application and local CLI in one repository, not a new npm module. `package.json` is marked private. The shared one-new-npm-module allocation for 2026-10-16 MYT remains unused.

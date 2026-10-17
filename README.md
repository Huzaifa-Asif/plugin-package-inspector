# Plugin Package Inspector

Plugin Package Inspector is a local-first preflight app for agent plugin packages. It checks package shape and release evidence without uploading files or asking for credentials.

It is intentionally an evidence aid, not a certification and not a substitute for current platform review. Rules are bounded and explain their limits.

## What it checks

- root `plugin.json`, portable schema fields, and required plugin name
- effective OpenAI settings using documented inline-over-overlay replacement precedence
- known OpenAI interface field types and separately labelled listing-readiness gaps
- current public-submission exclusions for app declarations and lifecycle hooks
- portable `skills/<name>/SKILL.md` paths
- optional MCP transport declaration
- privacy, security, support, and license files
- common secret signatures without including matched values in reports
- custom credential language needing manual review
- five-positive / three-negative review-case evidence for MCP app review (not skills-only packages)
- explicit manual gates: identity, organization ownership, video, release notes, reviewer access, domain and live-tool verification

## Use the browser app

Public demo: https://huzaifa-asif.github.io/plugin-package-inspector/

The hosted page processes selected package files locally in your browser. GitHub Pages handles delivery of the static app and logs visitor IP addresses for security as described in [Privacy](PRIVACY.md).

```sh
npm run serve
```

Open `http://127.0.0.1:4173`, extract the candidate ZIP, and choose its folder. The app reads selected files in the browser only. It makes no network requests.

## Use the CLI

```sh
node src/cli.mjs /path/to/extracted-plugin
node src/cli.mjs /path/to/extracted-plugin --json
```

Exit codes: `0` means no automated blocker, `1` means blocker(s), and `2` means inspection could not run. Warnings still require manual review.

Portable schema validity, OpenAI listing readiness, and current public-directory eligibility are intentionally separate findings. A package can be portable while still needing listing metadata or using app/hook features that are supported locally but currently excluded from public ZIP submission.

## Verify

```sh
npm run check
```

No install step or third-party runtime dependency is required. This repository is a private npm package (`private: true`) and is not allocated or published as a new npm module.

## Project documents

- [Privacy](PRIVACY.md)
- [Security policy](SECURITY.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Research and scope](docs/RESEARCH.md)
- [Release verification](docs/RELEASE_VERIFICATION.md)

## License

MIT

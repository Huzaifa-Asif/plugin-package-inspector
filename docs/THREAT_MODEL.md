# Threat model

## Assets

- unpublished plugin source and metadata
- filesystem paths
- credentials accidentally embedded in a candidate package
- integrity of the generated preflight report

## Trust boundaries

The browser receives only files selected through the browser picker or drag-and-drop. It has no backend. The CLI receives one explicit directory, skips symbolic links, bounds file count and scan size, and never executes candidate content.

## Material threats and controls

| Threat | Control | Residual risk |
| --- | --- | --- |
| Private package exfiltration | No fetch, form submission, analytics, remote fonts, service worker, or backend | A modified or third-party-hosted build could add network behavior; verify source and CSP |
| Secret disclosure in reports | Findings include detector type and path only | Filenames can still be sensitive; redact exported reports before sharing |
| Resource exhaustion | 2,000-file and 1 MB-per-file scan limits | Directory selection still exposes metadata for selected files to the page |
| Path escape in CLI | Resolve beneath supplied root and skip symbolic links | Concurrent filesystem mutation is outside this small tool's guarantees |
| False confidence | Explicit warning that preflight is heuristic and not approval | Users may ignore manual gates; UI and reports repeat them |
| Candidate code execution | Files are read as text and never imported, evaluated, or rendered as HTML | Browser and Node parser vulnerabilities remain platform risks |

## Out of scope

The inspector does not dynamically connect to MCP servers, execute skills, validate OAuth implementations, certify policy compliance, inspect Git history, or submit packages.

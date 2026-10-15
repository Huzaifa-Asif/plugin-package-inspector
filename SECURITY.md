# Security policy

Please report suspected vulnerabilities privately through GitHub security advisories for this repository. Do not attach real secrets, private packages, or customer data.

Supported version: the current `main` branch.

## Design controls

- no credential input or network request
- browser file access is explicit and session-scoped
- CLI traversal is limited to the supplied root and skips symbolic links
- file count, per-file, and 16 MiB aggregate scan limits bound memory use; browser reads are sequential
- the local server uses an exact route allowlist and accepts loopback Host values only
- secret findings include detector labels and paths, never matching values
- static server uses a restrictive Content Security Policy and denies traversal

The detector is heuristic. A clear result is not proof that a package is safe or eligible for publication.

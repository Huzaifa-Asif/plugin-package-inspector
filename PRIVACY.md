# Privacy

Plugin Package Inspector does not upload, transmit, persist, or monetize selected package files. The browser app reads files inside the active page only. The CLI reads only the directory explicitly supplied by the user and skips symbolic links.

The exported report contains finding descriptions and file paths, not source contents or detected credential values. A heuristic can miss credentials; inspect source control history and build artifacts separately.

The app stores only the light/dark theme preference in local browser storage. It includes no analytics, telemetry, cookies, accounts, ads, or remote services.

The public demo is served by GitHub Pages. GitHub states that it logs and stores a visitor's IP address for security when a Pages site is visited. This hosting metadata is handled by GitHub; the inspector does not send selected package files, file contents, or generated reports to GitHub or any other service.

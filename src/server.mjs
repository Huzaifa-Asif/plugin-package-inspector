import {createServer} from "node:http";
import {readFile} from "node:fs/promises";
import {extname, resolve} from "node:path";
import {fileURLToPath} from "node:url";

const root = resolve(import.meta.dirname, "..");
const port = Number(process.env.PORT || 4173);
const types = {".html":"text/html; charset=utf-8", ".css":"text/css; charset=utf-8", ".mjs":"text/javascript; charset=utf-8", ".svg":"image/svg+xml"};
const routes = new Map([
  ["/", "index.html"], ["/index.html", "index.html"], ["/src/styles.css", "src/styles.css"],
  ["/src/app.mjs", "src/app.mjs"], ["/src/audit.mjs", "src/audit.mjs"]
]);

export function resolveRoute(url, host, expectedPort = port) {
  const allowedHosts = new Set([`127.0.0.1:${expectedPort}`, `localhost:${expectedPort}`, `[::1]:${expectedPort}`]);
  if (!allowedHosts.has(host || "")) return null;
  const pathname = new URL(url || "/", "http://127.0.0.1").pathname;
  const route = routes.get(pathname);
  return route ? resolve(root, route) : null;
}

export const server = createServer(async (request, response) => {
  const target = resolveRoute(request.url, request.headers.host);
  if (!target) { response.writeHead(404, {"Content-Type":"text/plain; charset=utf-8"}).end("Not found"); return; }
  try {
    const body = await readFile(target);
    response.writeHead(200, {"Content-Type": types[extname(target)] || "application/octet-stream", "X-Content-Type-Options":"nosniff", "Content-Security-Policy":"default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"});
    response.end(body);
  } catch { response.writeHead(404).end("Not found"); }
});

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  server.listen(port, "127.0.0.1", () => console.log(`Plugin Package Inspector listening on http://127.0.0.1:${port}`));
}

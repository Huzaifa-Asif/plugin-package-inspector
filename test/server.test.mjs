import test from "node:test";
import assert from "node:assert/strict";
import {readFile} from "node:fs/promises";
import {resolveRoute} from "../src/server.mjs";

test("local server accepts only allowlisted routes on loopback hosts", () => {
  assert.match(resolveRoute("/", "127.0.0.1:4173"), /index\.html$/);
  assert.match(resolveRoute("/src/app.mjs", "localhost:4173"), /src\/app\.mjs$/);
  assert.equal(resolveRoute("/package.json", "127.0.0.1:4173"), null);
  assert.equal(resolveRoute("/.git/config", "127.0.0.1:4173"), null);
});

test("local server rejects arbitrary and mismatched Host headers", () => {
  assert.equal(resolveRoute("/", "evil.example"), null);
  assert.equal(resolveRoute("/", "127.0.0.1:9999"), null);
  assert.equal(resolveRoute("/%2e%2e/package.json", "127.0.0.1:4173"), null);
});

test("theme control exposes its next action without a contradictory pressed state", async () => {
  const [html, app] = await Promise.all([
    readFile(new URL("../index.html", import.meta.url), "utf8"),
    readFile(new URL("../src/app.mjs", import.meta.url), "utf8")
  ]);

  assert.doesNotMatch(html, /aria-pressed/);
  assert.match(html, /aria-label="Switch to light theme"/);
  assert.match(app, /setAttribute\("aria-label", `Switch to \$\{nextTheme\} theme`\)/);
  assert.doesNotMatch(app, /setAttribute\("aria-pressed"/);
});

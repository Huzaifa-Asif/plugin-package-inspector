import test from "node:test";
import assert from "node:assert/strict";
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

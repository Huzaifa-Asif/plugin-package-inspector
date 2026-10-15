import test from "node:test";
import assert from "node:assert/strict";
import {auditPackage} from "../src/audit.mjs";

const file = (path, text) => ({path, text, size: Buffer.byteLength(text)});
const manifest = JSON.stringify({
  $schema: "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json",
  name: "useful-plugin", version: "1.0.0", description: "Does useful work",
  homepage: "https://example.com", repository: "https://github.com/example/useful-plugin",
  extensions: {"com.openai": {interface: {displayName: "Useful Plugin"}}}
});
const reviewCases = "## Positive cases\n1. First\n2. Second\n3. Third\n4. Fourth\n5. Fifth\n\n## Negative cases\n1. First\n2. Second\n3. Third\n";
const valid = [
  file("plugin.json", manifest), file("skills/useful/SKILL.md", "---\nname: useful\ndescription: Inspect a synthetic package.\n---\n# Useful"),
  file("PRIVACY.md", "Local only"), file("SECURITY.md", "Report issues"), file("SUPPORT.md", "Support"),
  file("LICENSE", "MIT"), file("docs/REVIEW_CASES.md", reviewCases)
];

test("a complete skills-only package has no automated blockers", () => {
  const report = auditPackage(valid, {now: new Date("2026-10-16T00:00:00Z")});
  assert.equal(report.verdict, "preflight-clear");
  assert.equal(report.counts.fail, 0);
  assert.equal(report.generatedAt, "2026-10-16T00:00:00.000Z");
});

test("missing manifest and capability entry block preflight", () => {
  const report = auditPackage([file("README.md", "hello")]);
  assert.equal(report.verdict, "not-ready");
  assert.ok(report.findings.some((finding) => finding.id === "manifest-root" && finding.status === "fail"));
  assert.ok(report.findings.some((finding) => finding.id === "skills" && finding.status === "fail"));
});

test("invalid manifest JSON is reported without throwing", () => {
  const report = auditPackage([file("plugin.json", "{")]);
  assert.ok(report.findings.some((finding) => finding.id === "plugin.json-json"));
});

test("potential secrets report only detector labels and paths", () => {
  const report = auditPackage([...valid, file("notes.txt", "sk-exampleEXAMPLE123456789")]);
  const finding = report.findings.find((item) => item.id === "secrets");
  assert.equal(finding.status, "fail");
  assert.deepEqual(finding.paths, ["OpenAI-style key: notes.txt"]);
  assert.equal(JSON.stringify(report).includes("sk-exampleEXAMPLE123456789"), false);
});

test("Windows paths normalize to portable paths", () => {
  const report = auditPackage(valid.map((entry) => ({...entry, path: entry.path.replaceAll("/", "\\")})));
  assert.equal(report.counts.fail, 0);
});

test("an explicit MCP transport is recognized", () => {
  const report = auditPackage([...valid, file("mcp.json", JSON.stringify({$schema: "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json", mcpServers: {main: {type: "streamable-http", url: "https://example.com/mcp"}}}))]);
  assert.equal(report.findings.find((item) => item.id === "mcp-transport").status, "pass");
});

test("missing schema and unsupported manifest fields are blockers", () => {
  const broken = {...JSON.parse(manifest), unsupported: true};
  delete broken.$schema;
  const report = auditPackage(valid.map((entry) => entry.path === "plugin.json" ? file("plugin.json", JSON.stringify(broken)) : entry));
  assert.equal(report.findings.find((item) => item.id === "manifest-schema").status, "fail");
  assert.equal(report.findings.find((item) => item.id === "manifest-properties").status, "fail");
});

test("invalid MCP root and missing skill description are blockers", () => {
  const packageFiles = valid.map((entry) => entry.path.endsWith("SKILL.md") ? file(entry.path, "---\nname: useful\n---\n# Useful") : entry);
  packageFiles.push(file("mcp.json", JSON.stringify({servers: {main: {type: "streamable-http", url: "https://example.com/mcp"}}})));
  const report = auditPackage(packageFiles);
  assert.equal(report.findings.find((item) => item.id === "mcp-schema").status, "fail");
  assert.equal(report.findings.find((item) => item.id === "skill-metadata").status, "fail");
});

test("malformed JSON reports no candidate content", () => {
  const secret = "sk-sensitiveEXAMPLE123456789";
  const report = auditPackage([file("plugin.json", `{\"${secret}\":`)])
  assert.equal(JSON.stringify(report).includes(secret), false);
});

test("nested manifest types and quoted-empty skill metadata are blockers", () => {
  const broken = {...JSON.parse(manifest), author: "not-object", keywords: "not-array", extensions: {"com.openai": "not-object"}};
  const packageFiles = valid.map((entry) => {
    if (entry.path === "plugin.json") return file(entry.path, JSON.stringify(broken));
    if (entry.path.endsWith("SKILL.md")) return file(entry.path, "---\nname: useful\ndescription: \"\"\n---\n# Useful");
    return entry;
  });
  const report = auditPackage(packageFiles);
  assert.equal(report.findings.find((item) => item.id === "manifest-types").status, "fail");
  assert.equal(report.findings.find((item) => item.id === "skill-metadata").status, "fail");
});

test("MCP nested field types and additional properties are blockers", () => {
  const mcp = {$schema: "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json", mcpServers: {main: {type: "stdio", command: "node", args: "not-array", unexpected: true}}};
  const report = auditPackage([...valid, file("mcp.json", JSON.stringify(mcp))]);
  assert.equal(report.findings.find((item) => item.id === "mcp-transport").status, "fail");
});

test("portable MCP schema rejects server-level extension properties", () => {
  const mcp = {$schema: "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json", mcpServers: {main: {type: "streamable-http", url: "https://example.com/mcp", extensions: {"com.openai": {auth: {type: "none"}}}}}};
  const report = auditPackage([...valid, file("mcp.json", JSON.stringify(mcp))]);
  assert.equal(report.findings.find((item) => item.id === "mcp-transport").status, "fail");
});

test("skill metadata rejects YAML empty, null, boolean, collection, and numeric scalars", () => {
  for (const value of ['"" # empty', "null # empty", "false", "[]", "{}", "42"]) {
    const packageFiles = valid.map((entry) => entry.path.endsWith("SKILL.md") ? file(entry.path, `---\nname: useful\ndescription: ${value}\n---\n# Useful`) : entry);
    const report = auditPackage(packageFiles);
    assert.equal(report.findings.find((item) => item.id === "skill-metadata").status, "fail", value);
  }
});

test("valid JSON field names and metadata values cannot leak credential material", () => {
  const secret = "sk-EXAMPLESECRET123456789";
  const broken = {...JSON.parse(manifest), [secret]: true, name: secret, version: secret};
  const report = auditPackage(valid.map((entry) => entry.path === "plugin.json" ? file(entry.path, JSON.stringify(broken)) : entry));
  assert.equal(JSON.stringify(report).includes(secret), false);
});

test("custom credential language is a warning, not a fabricated rejection", () => {
  const custom = JSON.stringify({...JSON.parse(manifest), auth: {type: "api_key"}});
  const report = auditPackage(valid.map((entry) => entry.path === "plugin.json" ? file("plugin.json", custom) : entry));
  assert.equal(report.findings.find((item) => item.id === "auth-shape").status, "warn");
});

test("oversized files are not scanned and are explicitly reported", () => {
  const report = auditPackage([...valid, {path: "large.bin", text: "", size: 2_000_000}]);
  const finding = report.findings.find((item) => item.id === "file-size");
  assert.equal(finding.status, "fail");
  assert.deepEqual(finding.paths, ["large.bin"]);
});

test("aggregate package size is bounded independently of per-file size", () => {
  const chunks = Array.from({length: 17}, (_, index) => ({path: `data/${index}.txt`, text: "", size: 1024 * 1024}));
  const report = auditPackage([...valid, ...chunks]);
  assert.equal(report.findings.find((item) => item.id === "total-size").status, "fail");
});

test("skills-only packages do not receive MCP review-case warnings", () => {
  const withoutCases = valid.filter((entry) => !entry.path.endsWith("REVIEW_CASES.md"));
  const report = auditPackage(withoutCases);
  assert.equal(report.findings.find((item) => item.id === "review-cases").status, "info");
  assert.equal(report.verdict, "preflight-clear");
});

test("empty selection produces a bounded report", () => {
  const report = auditPackage([]);
  assert.equal(report.verdict, "not-ready");
  assert.equal(report.scope.fileCount, 0);
});

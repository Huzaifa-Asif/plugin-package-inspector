import test from "node:test";
import assert from "node:assert/strict";
import {auditPackage} from "../src/audit.mjs";

const file = (path, text) => ({path, text, size: Buffer.byteLength(text)});
const manifest = JSON.stringify({
  $schema: "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json",
  name: "useful-plugin", version: "1.0.0", description: "Does useful work",
  homepage: "https://example.com", repository: "https://github.com/example/useful-plugin",
  extensions: {"com.openai": {interface: {
    displayName: "Useful Plugin", shortDescription: "Inspect a package", longDescription: "Inspect a synthetic plugin package locally.",
    developerName: "Example", category: "Productivity", capabilities: ["Inspect packages"],
    websiteURL: "https://example.com", supportURL: "https://example.com/support",
    privacyPolicyURL: "https://example.com/privacy", termsOfServiceURL: "https://example.com/terms"
  }}}
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

test("inline OpenAI settings replace rather than merge the compatibility overlay", () => {
  const root = {...JSON.parse(manifest), extensions: {"com.openai": {interface: {displayName: "Inline only"}}}};
  const overlay = {
    interface: {
      displayName: "Overlay", shortDescription: "Complete overlay", longDescription: "This must not fill inline gaps.",
      developerName: "Example", category: "Productivity", websiteURL: "https://example.com",
      supportURL: "https://example.com/support", privacyPolicyURL: "https://example.com/privacy",
      termsOfServiceURL: "https://example.com/terms"
    },
    extensions: {"com.openai": {publication: {countries: ["US"]}}}
  };
  const packageFiles = valid.map((entry) => entry.path === "plugin.json" ? file(entry.path, JSON.stringify(root)) : entry);
  const report = auditPackage([...packageFiles, file(".codex-plugin/plugin.json", JSON.stringify(overlay))]);
  const source = report.findings.find((item) => item.id === "openai-settings-source");
  assert.equal(source.status, "pass");
  assert.deepEqual(source.paths, ["plugin.json"]);
  assert.match(source.detail, /not merged/i);
  assert.equal(report.findings.find((item) => item.id === "openai-submission-metadata").status, "pass");
  assert.equal(report.findings.find((item) => item.id === "openai-submission-readiness").status, "warn");
});

test("compatibility overlay supplies effective settings and exposes submission exclusions", () => {
  const root = JSON.parse(manifest);
  delete root.extensions;
  const overlay = {
    interface: {
      displayName: "Useful Plugin", shortDescription: "Inspect a package", longDescription: "Inspect a synthetic plugin package locally.",
      developerName: "Example", category: "Productivity", capabilities: ["Inspect packages"],
      websiteURL: "https://example.com", supportURL: "https://example.com/support",
      privacyPolicyURL: "https://example.com/privacy", termsOfServiceURL: "https://example.com/terms"
    },
    apps: "./.app.json",
    hooks: "./hooks/hooks.json"
  };
  const packageFiles = valid.map((entry) => entry.path === "plugin.json" ? file(entry.path, JSON.stringify(root)) : entry);
  packageFiles.push(file(".codex-plugin/plugin.json", JSON.stringify(overlay)), file(".app.json", "{}"), file("hooks/hooks.json", "{}"));
  const report = auditPackage(packageFiles);
  const source = report.findings.find((item) => item.id === "openai-settings-source");
  assert.deepEqual(source.paths, [".codex-plugin/plugin.json"]);
  assert.match(source.detail, /overlay supplies/i);
  const exclusion = report.findings.find((item) => item.id === "openai-submission-exclusions");
  assert.equal(exclusion.status, "fail");
  assert.deepEqual(exclusion.paths, [".codex-plugin/plugin.json", ".app.json", "hooks/hooks.json"]);
});

test("portable validity is separate from OpenAI submission metadata readiness", () => {
  const portable = {$schema: "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json", name: "minimal-plugin", extensions: {"com.openai": {interface: {displayName: "Useful Plugin"}}}};
  const report = auditPackage(valid.map((entry) => entry.path === "plugin.json" ? file(entry.path, JSON.stringify(portable)) : entry));
  assert.equal(report.findings.find((item) => item.id === "manifest-core").status, "pass");
  assert.equal(report.findings.find((item) => item.id === "manifest-types").status, "pass");
  assert.equal(report.findings.find((item) => item.id === "openai-submission-metadata").status, "pass");
  assert.equal(report.findings.find((item) => item.id === "openai-submission-readiness").status, "warn");
  assert.equal(report.findings.find((item) => item.id === "openai-submission-exclusions").status, "pass");
});

test("portable dotted names warn for OpenAI submission without becoming portable failures", () => {
  const dotted = {...JSON.parse(manifest), name: "useful.plugin"};
  const report = auditPackage(valid.map((entry) => entry.path === "plugin.json" ? file(entry.path, JSON.stringify(dotted)) : entry));
  assert.equal(report.findings.find((item) => item.id === "manifest-core").status, "pass");
  assert.equal(report.findings.find((item) => item.id === "manifest-name"), undefined);
  assert.equal(report.findings.find((item) => item.id === "manifest-types").status, "pass");
  assert.equal(report.findings.find((item) => item.id === "openai-submission-name").status, "warn");
  assert.equal(report.counts.fail, 0);
  assert.equal(report.verdict, "needs-review");
});

test("invalid OpenAI field types warn without changing portable validity", () => {
  const portable = {$schema: "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json", name: "typed-plugin", extensions: {"com.openai": {interface: {displayName: "Typed", websiteURL: 42, defaultPrompt: ["Valid", 7]}}}};
  const report = auditPackage(valid.map((entry) => entry.path === "plugin.json" ? file(entry.path, JSON.stringify(portable)) : entry));
  assert.equal(report.findings.find((item) => item.id === "manifest-core").status, "pass");
  assert.equal(report.findings.find((item) => item.id === "manifest-types").status, "pass");
  assert.equal(report.findings.find((item) => item.id === "openai-submission-metadata").status, "warn");
});

test("OpenAI defaultPrompt accepts a non-empty string or string array", () => {
  for (const defaultPrompt of ["Try this plugin", ["Try this plugin"]]) {
    const candidate = {...JSON.parse(manifest), extensions: {"com.openai": {interface: {...JSON.parse(manifest).extensions["com.openai"].interface, defaultPrompt}}}};
    const report = auditPackage(valid.map((entry) => entry.path === "plugin.json" ? file(entry.path, JSON.stringify(candidate)) : entry));
    assert.equal(report.findings.find((item) => item.id === "openai-submission-metadata").status, "pass");
  }
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

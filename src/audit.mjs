const MAX_FILE_BYTES = 1024 * 1024;
const MAX_FILES = 2000;
const MAX_TOTAL_BYTES = 16 * 1024 * 1024;
const PLUGIN_SCHEMA = "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json";
const MCP_SCHEMA = "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json";
const PLUGIN_KEYS = new Set(["$schema", "name", "version", "description", "author", "homepage", "repository", "license", "keywords", "extensions"]);
const OPENAI_INTERFACE_STRINGS = [
  "displayName", "shortDescription", "longDescription", "developerName", "category",
  "websiteURL", "supportURL", "privacyPolicyURL", "termsOfServiceURL", "brandColor",
  "brandColorDark", "composerIcon", "composerIconDark", "logo", "logoDark"
];
const OPENAI_COMMON_LISTING_FIELDS = [
  "displayName", "shortDescription", "longDescription", "developerName", "category",
  "websiteURL", "supportURL", "privacyPolicyURL", "termsOfServiceURL"
];
const SECRET_PATTERNS = [
  {label: "OpenAI-style key", pattern: /\bsk-[A-Za-z0-9_-]{16,}\b/g},
  {label: "GitHub token", pattern: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g},
  {label: "private key block", pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g},
  {label: "bearer token literal", pattern: /authorization\s*[:=]\s*["']?bearer\s+[A-Za-z0-9._~+\/-]{12,}/gi}
];

const normalizePath = (value) => String(value || "").replaceAll("\\", "/").replace(/^\.\//, "");
const finding = (id, status, title, detail, paths = []) => ({id, status, title, detail, paths});

function parseJson(file, label, findings) {
  try {
    const value = JSON.parse(file.text);
    if (!value || Array.isArray(value) || typeof value !== "object") throw new Error("root must be an object");
    return value;
  } catch (error) {
    findings.push(finding(`${label}-json`, "fail", `${label} is not valid JSON`, "JSON parsing failed. Candidate content is omitted from this report.", [file.path]));
    return null;
  }
}

function hasString(value) {
  return typeof value === "string" && value.trim().length > 0;
}

export function auditPackage(inputFiles, options = {}) {
  const files = inputFiles.map((file) => ({
    path: normalizePath(file.path),
    text: typeof file.text === "string" ? file.text : "",
    size: Number.isFinite(file.size) ? file.size : new TextEncoder().encode(file.text || "").length
  })).filter((file) => file.path && !file.path.startsWith("__MACOSX/") && !file.path.endsWith("/.DS_Store"));
  const findings = [];
  const generatedAt = options.now instanceof Date ? options.now.toISOString() : new Date().toISOString();

  if (files.length === 0) {
    findings.push(finding("files-empty", "fail", "No package files selected", "Choose the plugin package directory. Files stay in this browser session."));
    return finish(files, findings, generatedAt);
  }
  if (files.length > MAX_FILES) findings.push(finding("files-count", "fail", "Package is too large to inspect safely", `${files.length} files exceeds the ${MAX_FILES}-file local limit.`));
  const totalBytes = files.reduce((sum, file) => sum + file.size, 0);
  findings.push(totalBytes > MAX_TOTAL_BYTES
    ? finding("total-size", "fail", "Package exceeds the aggregate scan bound", `${totalBytes.toLocaleString()} bytes exceeds the ${MAX_TOTAL_BYTES.toLocaleString()}-byte local limit.`)
    : finding("total-size", "pass", "Aggregate package size is within the scan bound", `${totalBytes.toLocaleString()} of ${MAX_TOTAL_BYTES.toLocaleString()} bytes.`));
  const oversized = files.filter((file) => file.size > MAX_FILE_BYTES).map((file) => file.path);
  findings.push(oversized.length
    ? finding("file-size", "fail", "Oversized files need manual review", `Files over ${MAX_FILE_BYTES.toLocaleString()} bytes are not scanned.`, oversized)
    : finding("file-size", "pass", "File sizes are within the local scan bound", `${files.length} files inspected; maximum ${MAX_FILE_BYTES.toLocaleString()} bytes per file.`));

  const byPath = new Map(files.map((file) => [file.path, file]));
  const manifestFile = byPath.get("plugin.json");
  const overlayFile = byPath.get(".codex-plugin/plugin.json");
  let manifest = null;
  let overlay = null;
  if (!manifestFile) {
    findings.push(finding("manifest-root", "fail", "Root plugin.json is missing", "Place plugin.json at the package root, not inside a nested folder."));
  } else {
    findings.push(finding("manifest-root", "pass", "Root plugin.json found", "The package has a root manifest.", ["plugin.json"]));
    manifest = parseJson(manifestFile, "plugin.json", findings);
  }
  if (overlayFile) overlay = parseJson(overlayFile, ".codex-plugin/plugin.json", findings);

  if (manifest) {
    const unknownKeys = Object.keys(manifest).filter((key) => !PLUGIN_KEYS.has(key));
    findings.push(unknownKeys.length
      ? finding("manifest-properties", "fail", "plugin.json has unsupported top-level fields", `${unknownKeys.length} unsupported top-level ${unknownKeys.length === 1 ? "field" : "fields"} detected; candidate field names are omitted.`, ["plugin.json"])
      : finding("manifest-properties", "pass", "plugin.json top-level fields are supported", "No additional top-level properties detected.", ["plugin.json"]));
    findings.push(manifest.$schema === PLUGIN_SCHEMA
      ? finding("manifest-schema", "pass", "Portable manifest schema is current", PLUGIN_SCHEMA, ["plugin.json"])
      : finding("manifest-schema", "fail", "Portable manifest schema is missing or unsupported", `Expected ${PLUGIN_SCHEMA}.`, ["plugin.json"]));
    findings.push(!hasString(manifest.name)
      ? finding("manifest-core", "fail", "Portable plugin name is missing or empty", "The portable schema requires a non-empty name. The $schema requirement is reported separately.", ["plugin.json"])
      : finding("manifest-core", "pass", "Portable required metadata is present", "The required plugin name is non-empty. The $schema requirement is reported separately; version and description are optional.", ["plugin.json"]));
    if (hasString(manifest.name) && !/^(?!.*(?:--|\.\.))[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(manifest.name)) {
      findings.push(finding("manifest-name", "fail", "Plugin name is not portable", "Use 1–64 lowercase letters, digits, dots, or hyphens; avoid consecutive hyphens or dots.", ["plugin.json"]));
    } else if (hasString(manifest.name) && manifest.name.length > 64) {
      findings.push(finding("manifest-name", "fail", "Plugin name is too long", "Portable names are limited to 64 characters.", ["plugin.json"]));
    }
    const nestedIssues = validateManifestFields(manifest);
    findings.push(nestedIssues
      ? finding("manifest-types", "fail", "Portable manifest field types are invalid", `${nestedIssues} schema type or nested-property ${nestedIssues === 1 ? "issue" : "issues"} detected; candidate values are omitted.`, ["plugin.json"])
      : finding("manifest-types", "pass", "Portable manifest field types are valid", "Optional author, URL, keyword, and extension fields match the portable schema.", ["plugin.json"]));
    const inlineOpenAi = isObject(manifest.extensions?.["com.openai"]) ? manifest.extensions["com.openai"] : null;
    const overlayOpenAi = normalizeOpenAiOverlay(overlay);
    const effectiveOpenAi = inlineOpenAi || overlayOpenAi;
    const effectiveSource = inlineOpenAi ? "plugin.json" : overlayOpenAi ? ".codex-plugin/plugin.json" : null;
    findings.push(effectiveSource
      ? finding("openai-settings-source", "pass", "Effective OpenAI settings resolved", inlineOpenAi
        ? "Using inline extensions.com.openai from plugin.json; the compatibility overlay is not merged."
        : "Inline extensions.com.openai is absent, so the compatibility overlay supplies OpenAI-specific settings.", [effectiveSource])
      : finding("openai-settings-source", "warn", "OpenAI-specific settings are absent", "The package can be portable without them, but an OpenAI submission needs current listing metadata."));
    if (effectiveOpenAi) {
      const metadataIssues = countOpenAiSubmissionMetadataTypeIssues(effectiveOpenAi);
      const listingGaps = countOpenAiCommonListingGaps(effectiveOpenAi);
      findings.push(metadataIssues
        ? finding("openai-submission-metadata", "warn", "OpenAI metadata field types need review", `${metadataIssues} known interface field ${metadataIssues === 1 ? "has" : "fields have"} an unsupported value type. Portable schema validity is reported separately.`, [effectiveSource])
        : isObject(effectiveOpenAi.interface)
          ? finding("openai-submission-metadata", "pass", "Known OpenAI metadata field types are valid", "Fields that are present use supported value types. This structural check does not certify listing completeness or portal acceptance.", [effectiveSource])
          : finding("openai-submission-metadata", "info", "No OpenAI interface metadata to type-check", "OpenAI-specific settings are present, but interface listing metadata is absent. Portable schema validity is reported separately.", [effectiveSource]));
      findings.push(listingGaps
        ? finding("openai-submission-readiness", "warn", "OpenAI listing metadata is incomplete", `${listingGaps} commonly documented listing ${listingGaps === 1 ? "field is" : "fields are"} absent. Exact portal requirements depend on plugin architecture and human review; portable validity is unaffected.`, [effectiveSource])
        : finding("openai-submission-readiness", "info", "Common OpenAI listing metadata is present", "Portal requirements remain architecture-dependent and subject to human review; this is not an acceptance guarantee.", [effectiveSource]));
    } else {
      findings.push(finding("openai-submission-metadata", "info", "No OpenAI submission metadata to inspect", "Portable validity does not imply directory-submission readiness."));
      findings.push(finding("openai-submission-readiness", "info", "OpenAI listing readiness was not assessed", "No effective OpenAI interface settings were found. Portable validity is unaffected."));
    }
    const exclusions = findOpenAiSubmissionExclusions(files, inlineOpenAi, overlay);
    findings.push(exclusions.length
      ? finding("openai-submission-exclusions", "fail", "Package is not currently eligible for public directory submission", "App references and lifecycle hooks are supported for local Codex distribution but are currently excluded from public plugin ZIP submission.", exclusions)
      : finding("openai-submission-exclusions", "pass", "No current app or lifecycle-hook submission exclusion found", "Portable validity and submission eligibility are separate checks."));
    const urls = ["homepage", "repository"].filter((key) => hasString(manifest[key]) && !/^https:\/\//i.test(manifest[key]));
    if (urls.length) findings.push(finding("manifest-urls", "warn", "Public metadata contains non-HTTPS URLs", `Review: ${urls.join(", ")}.`, ["plugin.json"]));
  }

  const skillFiles = files.filter((file) => /^skills\/[^/]+\/SKILL\.md$/.test(file.path));
  const misplacedSkills = files.filter((file) => file.path.endsWith("SKILL.md") && !/^skills\/[^/]+\/SKILL\.md$/.test(file.path)).map((file) => file.path);
  findings.push(skillFiles.length
    ? finding("skills", "pass", `${skillFiles.length} skill ${skillFiles.length === 1 ? "entry" : "entries"} found`, "Each skill is in skills/<name>/SKILL.md.", skillFiles.map((file) => file.path))
    : finding("skills", byPath.has("mcp.json") ? "info" : "fail", "No packaged skill entry found", byPath.has("mcp.json") ? "MCP-only packages can be valid; confirm the intended architecture." : "Add at least one skill or an mcp.json connection."));
  const invalidSkills = skillFiles.flatMap((file) => validateSkill(file));
  findings.push(invalidSkills.length
    ? finding("skill-metadata", "fail", "Skill metadata is incomplete", "Every SKILL.md must begin with frontmatter containing non-empty name and description fields.", invalidSkills)
    : skillFiles.length ? finding("skill-metadata", "pass", "Skill metadata is present", "Every discovered skill declares a name and description.", skillFiles.map((file) => file.path)) : finding("skill-metadata", "info", "No skill metadata to inspect", "This can be valid for an MCP-only package."));
  if (misplacedSkills.length) findings.push(finding("skills-path", "warn", "SKILL.md files outside the portable path", "These files may not be discovered as packaged skills.", misplacedSkills));

  const mcpFile = byPath.get("mcp.json");
  if (mcpFile) {
    const mcp = parseJson(mcpFile, "mcp.json", findings);
    if (mcp) {
      const unknownMcpKeys = Object.keys(mcp).filter((key) => !["$schema", "mcpServers"].includes(key));
      const servers = mcp.mcpServers;
      const shapeValid = mcp.$schema === MCP_SCHEMA && servers && typeof servers === "object" && !Array.isArray(servers) && !unknownMcpKeys.length;
      findings.push(shapeValid
        ? finding("mcp-schema", "pass", "MCP configuration has the portable root shape", `${Object.keys(servers).length} named server entries.`, ["mcp.json"])
        : finding("mcp-schema", "fail", "MCP configuration root is invalid", `Require $schema=${MCP_SCHEMA} and an mcpServers object with no other top-level fields.`, ["mcp.json"]));
      if (shapeValid) {
        const invalidServers = Object.values(servers).filter((server) => !validMcpServer(server));
        findings.push(invalidServers.length
          ? finding("mcp-transport", "fail", "One or more MCP server entries are invalid", `${invalidServers.length} server ${invalidServers.length === 1 ? "entry has" : "entries have"} an unsupported field, type, or connection value. Candidate server names are omitted.`, ["mcp.json"])
          : finding("mcp-transport", "pass", "MCP transports are explicit", "Supported transport and required connection fields detected.", ["mcp.json"]));
      }
    }
  } else {
    findings.push(finding("mcp-optional", "info", "No MCP connection packaged", "This is expected for a skills-only package."));
  }

  const docGroups = [
    ["privacy", ["PRIVACY.md", "docs/PRIVACY.md"]],
    ["security", ["SECURITY.md", "docs/SECURITY.md"]],
    ["support", ["SUPPORT.md", "docs/SUPPORT.md"]],
    ["license", ["LICENSE", "LICENSE.md"]]
  ];
  const missingDocs = docGroups.filter(([, choices]) => !choices.some((path) => byPath.has(path))).map(([name]) => name);
  findings.push(missingDocs.length
    ? finding("trust-docs", "warn", "Trust documentation is incomplete", `Not found: ${missingDocs.join(", ")}. Some may be hosted externally; verify listing links manually.`)
    : finding("trust-docs", "pass", "Privacy, security, support, and license files found", "Confirm public URLs resolve before submission."));

  const secretHits = [];
  for (const file of files) {
    if (file.size > MAX_FILE_BYTES) continue;
    for (const detector of SECRET_PATTERNS) {
      detector.pattern.lastIndex = 0;
      if (detector.pattern.test(file.text)) secretHits.push(`${detector.label}: ${file.path}`);
    }
  }
  findings.push(secretHits.length
    ? finding("secrets", "fail", "Potential credential material detected", "Remove and rotate any real secret. This heuristic reports paths only and never includes matched values.", secretHits)
    : finding("secrets", "pass", "No common credential signatures detected", "Heuristic scan only; review history and generated artifacts separately."));

  const authText = files.filter((file) => /(?:plugin|mcp)\.json$/.test(file.path)).map((file) => file.text).join("\n");
  if (/api[_ -]?key|basic\s+auth|bearer\s+header/i.test(authText)) {
    findings.push(finding("auth-shape", "warn", "Custom credential language needs review", "Public directory flows do not accept every custom credential pattern. Do not collect API keys or secrets in skills or UI."));
  } else {
    findings.push(finding("auth-shape", "pass", "No custom API-key flow declared in package metadata", "Still verify runtime tools and documentation."));
  }

  const reviewFile = byPath.get("docs/REVIEW_CASES.md") || byPath.get("REVIEW_CASES.md");
  if (mcpFile && reviewFile) {
    const positive = countReviewCases(reviewFile.text, "positive");
    const negative = countReviewCases(reviewFile.text, "negative");
    findings.push(positive >= 5 && negative >= 3
      ? finding("review-cases", "pass", "Review case evidence is present", `Detected at least ${positive} positive and ${negative} negative labels. Inspect scenario quality manually.`, [reviewFile.path])
      : finding("review-cases", "warn", "Review cases may be incomplete", `Detected ${positive} positive and ${negative} negative labels; current submission guidance asks for five positive and three negative tests.`, [reviewFile.path]));
  } else if (mcpFile) {
    findings.push(finding("review-cases", "warn", "Review case evidence is not packaged", "Prepare five positive and three negative tests for submission. This evidence may live outside the distributable ZIP."));
  } else {
    findings.push(finding("review-cases", "info", "MCP review-case count does not apply", "The five-positive / three-negative submission evidence is an MCP review requirement, not a generic skills-only package requirement."));
  }

  findings.push(finding("manual-gates", "info", "Manual submission gates remain", "Verify ownership and identity, listing text, release notes, walkthrough video, reviewer access where needed, live endpoints, domain ownership, and human approval. This tool cannot certify acceptance."));
  return finish(files, findings, generatedAt);
}

function validateSkill(file) {
  const match = /^---\s*\r?\n([\s\S]*?)\r?\n---(?:\s*\r?\n|$)/.exec(file.text);
  if (!match) return [file.path];
  const name = yamlScalar(/^name:\s*(.*?)\s*$/m.exec(match[1])?.[1]);
  const description = yamlScalar(/^description:\s*(.*?)\s*$/m.exec(match[1])?.[1]);
  return name && description ? [] : [file.path];
}

function validMcpServer(server) {
  if (!server || typeof server !== "object" || Array.isArray(server)) return false;
  if (server.type === "stdio") {
    if (Object.keys(server).some((key) => !["type", "command", "args", "env", "cwd"].includes(key))) return false;
    if (!hasString(server.command)) return false;
    if (server.args !== undefined && (!Array.isArray(server.args) || server.args.some((value) => typeof value !== "string"))) return false;
    if (server.env !== undefined && (!isObject(server.env) || Object.entries(server.env).some(([key, value]) => ["PLUGIN_ROOT", "PLUGIN_DATA"].includes(key) || typeof value !== "string"))) return false;
    if (server.cwd !== undefined && (typeof server.cwd !== "string" || !/^(?:\.\/|\$\{PLUGIN_ROOT\}(?:\/|$)|\$\{PLUGIN_DATA\}(?:\/|$))/.test(server.cwd))) return false;
    return true;
  }
  if (server.type === "streamable-http" || server.type === "sse") {
    if (Object.keys(server).some((key) => !["type", "url", "headers"].includes(key))) return false;
    if (!hasString(server.url)) return false;
    if (server.headers !== undefined && (!isObject(server.headers) || Object.values(server.headers).some((value) => typeof value !== "string"))) return false;
    return true;
  }
  return false;
}

function validateManifestFields(manifest) {
  let issues = 0;
  for (const key of ["version", "description", "homepage", "repository", "license"]) {
    if (manifest[key] !== undefined && typeof manifest[key] !== "string") issues += 1;
  }
  if (manifest.author !== undefined) {
    if (!isObject(manifest.author)) issues += 1;
    else {
      if (Object.keys(manifest.author).some((key) => !["name", "email", "url"].includes(key))) issues += 1;
      if (Object.values(manifest.author).some((value) => typeof value !== "string")) issues += 1;
    }
  }
  if (manifest.keywords !== undefined && (!Array.isArray(manifest.keywords) || manifest.keywords.some((value) => typeof value !== "string"))) issues += 1;
  if (manifest.extensions !== undefined && (!isObject(manifest.extensions) || Object.values(manifest.extensions).some((value) => !isObject(value)))) issues += 1;
  return issues;
}

function normalizeOpenAiOverlay(overlay) {
  if (!isObject(overlay)) return null;
  const nested = isObject(overlay.extensions?.["com.openai"]) ? overlay.extensions["com.openai"] : {};
  const direct = {};
  for (const key of ["interface", "apps", "hooks", "onboardingSkill"]) {
    if (Object.hasOwn(overlay, key)) direct[key] = overlay[key];
  }
  const settings = {...nested, ...direct};
  return Object.keys(settings).length ? settings : null;
}

function countOpenAiSubmissionMetadataTypeIssues(settings) {
  if (!isObject(settings.interface)) return settings.interface === undefined ? 0 : 1;
  let issues = OPENAI_INTERFACE_STRINGS.filter((key) => settings.interface[key] !== undefined && !hasString(settings.interface[key])).length;
  if (settings.interface.capabilities !== undefined && (!Array.isArray(settings.interface.capabilities) || settings.interface.capabilities.some((value) => !hasString(value)))) issues += 1;
  if (settings.interface.defaultPrompt !== undefined && !hasString(settings.interface.defaultPrompt)
    && (!Array.isArray(settings.interface.defaultPrompt) || settings.interface.defaultPrompt.some((value) => !hasString(value)))) issues += 1;
  return issues;
}

function countOpenAiCommonListingGaps(settings) {
  if (!isObject(settings.interface)) return OPENAI_COMMON_LISTING_FIELDS.length;
  return OPENAI_COMMON_LISTING_FIELDS.filter((key) => !hasString(settings.interface[key])).length;
}

function findOpenAiSubmissionExclusions(files, inlineOpenAi, overlay) {
  const paths = new Set();
  if (hasSubmissionExcludedSetting(inlineOpenAi)) paths.add("plugin.json");
  const overlayNested = isObject(overlay?.extensions?.["com.openai"]) ? overlay.extensions["com.openai"] : null;
  if (hasSubmissionExcludedSetting(overlay) || hasSubmissionExcludedSetting(overlayNested)) paths.add(".codex-plugin/plugin.json");
  for (const file of files) {
    if (file.path.endsWith(".app.json") || file.path.startsWith("hooks/")) paths.add(file.path);
  }
  return [...paths];
}

function hasSubmissionExcludedSetting(settings) {
  return isObject(settings) && (Object.hasOwn(settings, "apps") || Object.hasOwn(settings, "hooks"));
}

function isObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function yamlScalar(value) {
  if (!hasString(value)) return "";
  const trimmed = value.trim();
  const doubleQuoted = /^"((?:[^"\\]|\\.)*)"\s*(?:#.*)?$/.exec(trimmed);
  if (doubleQuoted) return doubleQuoted[1].trim();
  const singleQuoted = /^'((?:[^']|'')*)'\s*(?:#.*)?$/.exec(trimmed);
  if (singleQuoted) return singleQuoted[1].replaceAll("''", "'").trim();
  const unquoted = trimmed.replace(/\s+#.*$/, "").trim();
  if (!unquoted || /^(?:null|~|true|false|yes|no|on|off|\[.*\]|\{.*\}|[-+]?\d+(?:\.\d+)?)$/i.test(unquoted)) return "";
  if (/^[&*!>|%@`]/.test(unquoted)) return "";
  return unquoted;
}

function countReviewCases(text, label) {
  const heading = new RegExp(`^#{1,6}\\s+${label}(?:\\s+cases?)?\\s*$`, "im").exec(text);
  if (!heading) return (text.match(new RegExp(`\\b${label}\\b`, "gi")) || []).length;
  const sectionStart = heading.index + heading[0].length;
  const remainder = text.slice(sectionStart);
  const nextHeading = /^#{1,6}\s+/m.exec(remainder);
  const section = nextHeading ? remainder.slice(0, nextHeading.index) : remainder;
  return (section.match(/^\s*(?:\d+[.)]|[-*+])\s+/gm) || []).length;
}

function finish(files, findings, generatedAt) {
  const counts = {pass: 0, warn: 0, fail: 0, info: 0};
  for (const item of findings) counts[item.status] += 1;
  return {
    schemaVersion: 1,
    generatedAt,
    scope: {fileCount: files.length, localOnly: true, maxFiles: MAX_FILES, maxFileBytes: MAX_FILE_BYTES},
    verdict: counts.fail ? "not-ready" : counts.warn ? "needs-review" : "preflight-clear",
    counts,
    findings
  };
}

export const limits = Object.freeze({maxFiles: MAX_FILES, maxFileBytes: MAX_FILE_BYTES, maxTotalBytes: MAX_TOTAL_BYTES});

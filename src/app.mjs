import {auditPackage, limits} from "./audit.mjs";

const input = document.querySelector("#folder-input");
const dropzone = document.querySelector("#dropzone");
const results = document.querySelector("#results");
const summary = document.querySelector("#summary");
const exportButton = document.querySelector("#export-report");
const clearButton = document.querySelector("#clear-report");
const themeButton = document.querySelector("#theme-toggle");
let currentReport = null;

const icons = {pass: "✓", warn: "!", fail: "×", info: "i"};

function setBusy(value) {
  dropzone.setAttribute("aria-busy", String(value));
  input.disabled = value;
}

async function readSelection(fileList) {
  const selected = [...fileList].slice(0, limits.maxFiles + 1);
  const folderPrefix = commonFolderPrefix(selected);
  setBusy(true);
  summary.textContent = `Reading ${selected.length.toLocaleString()} local files…`;
  try {
    const files = [];
    let readBytes = 0;
    for (const file of selected) {
      const withinBudget = file.size <= limits.maxFileBytes && readBytes + file.size <= limits.maxTotalBytes;
      files.push({
        path: folderPrefix ? file.webkitRelativePath.slice(folderPrefix.length) : file.webkitRelativePath || file.name,
        size: file.size,
        text: withinBudget ? await file.text() : ""
      });
      if (withinBudget) readBytes += file.size;
    }
    render(auditPackage(files));
  } catch {
    summary.textContent = "The selected files could not be read. Nothing was uploaded.";
  } finally {
    setBusy(false);
    input.value = "";
  }
}

function commonFolderPrefix(files) {
  if (!files.length || files.some((file) => !file.webkitRelativePath.includes("/"))) return "";
  const first = `${files[0].webkitRelativePath.split("/")[0]}/`;
  return files.every((file) => file.webkitRelativePath.startsWith(first)) ? first : "";
}

function render(report) {
  currentReport = report;
  exportButton.disabled = false;
  clearButton.disabled = false;
  summary.innerHTML = `<strong>${labelVerdict(report.verdict)}</strong><span>${report.scope.fileCount} files · ${report.counts.fail} blockers · ${report.counts.warn} review items</span>`;
  results.replaceChildren(...report.findings.map((item) => {
    const article = document.createElement("article");
    article.className = `finding finding--${item.status}`;
    const marker = document.createElement("span");
    marker.className = "finding__marker";
    marker.setAttribute("aria-hidden", "true");
    marker.textContent = icons[item.status];
    const content = document.createElement("div");
    const heading = document.createElement("h3");
    heading.textContent = item.title;
    const meta = document.createElement("span");
    meta.className = "finding__status";
    meta.textContent = item.status;
    heading.append(meta);
    const detail = document.createElement("p");
    detail.textContent = item.detail;
    content.append(heading, detail);
    if (item.paths?.length) {
      const paths = document.createElement("ul");
      for (const path of item.paths.slice(0, 12)) {
        const li = document.createElement("li");
        li.textContent = path;
        paths.append(li);
      }
      if (item.paths.length > 12) {
        const li = document.createElement("li");
        li.textContent = `…and ${item.paths.length - 12} more`;
        paths.append(li);
      }
      content.append(paths);
    }
    article.append(marker, content);
    return article;
  }));
  results.focus();
}

function labelVerdict(value) {
  return {"not-ready": "Blockers found", "needs-review": "Manual review needed", "preflight-clear": "Automated preflight clear"}[value];
}

function clear() {
  currentReport = null;
  exportButton.disabled = true;
  clearButton.disabled = true;
  summary.textContent = "No package inspected yet.";
  results.replaceChildren();
  input.focus();
}

function exportReport() {
  if (!currentReport) return;
  const blob = new Blob([`${JSON.stringify(currentReport, null, 2)}\n`], {type: "application/json"});
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = "plugin-package-preflight.json";
  link.click();
  URL.revokeObjectURL(link.href);
}

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  const nextTheme = theme === "light" ? "dark" : "light";
  themeButton.setAttribute("aria-label", `Switch to ${nextTheme} theme`);
  themeButton.querySelector("span").textContent = `${nextTheme[0].toUpperCase()}${nextTheme.slice(1)}`;
  try { localStorage.setItem("ppi-theme", theme); } catch {}
}

input.addEventListener("change", () => input.files?.length && readSelection(input.files));
exportButton.addEventListener("click", exportReport);
clearButton.addEventListener("click", clear);
themeButton.addEventListener("click", () => applyTheme(document.documentElement.dataset.theme === "light" ? "dark" : "light"));

let stored = null;
try { stored = localStorage.getItem("ppi-theme"); } catch {}
applyTheme(stored || (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark"));

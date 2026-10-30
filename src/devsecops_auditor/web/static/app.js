"use strict";

// Remove any form values that an earlier normal form submission put in the URL.
if (window.location.search) {
  window.history.replaceState(
    null,
    "",
    `${window.location.pathname}${window.location.hash}`
  );
}

const zipInput = document.getElementById("zipInput");
const zipFileName = document.getElementById("zipFileName");
const scanZipButton = document.getElementById("scanZipButton");
const repositoryForm = document.getElementById("repoForm");
const repositoryUrlInput = document.getElementById("repoUrl");
const githubTokenInput = document.getElementById("githubToken");
const repositoryButton = document.getElementById("scanRepositoryButton");
const processStatusText = document.getElementById("processStatusText");
const progressTrack = document.getElementById("progressTrack");
const progressFill = document.getElementById("progressFill");
const activityLog = document.getElementById("activityLog");
const downloadReportButton = document.getElementById("downloadReportButton");
const downloadProjectButton = document.getElementById("downloadProjectButton");

const agentNames = ["code", "dependencies", "secrets"];

let selectedZip = null;
let latestFindings = [];
let scanInProgress = false;
let activeSource = null;

scanZipButton.disabled = true;

function updateProgress(message, progress) {
  const safeProgress = Math.max(0, Math.min(100, Number(progress) || 0));

  processStatusText.textContent = message;
  progressFill.style.width = `${safeProgress}%`;
  progressTrack.setAttribute("aria-valuenow", String(safeProgress));
}

function addActivity(message) {
  const item = document.createElement("li");
  item.textContent = message;
  activityLog.appendChild(item);

  while (activityLog.children.length > 5) {
    activityLog.removeChild(activityLog.firstElementChild);
  }
}

function resetAgentCards() {
  for (const name of agentNames) {
    const card = document.querySelector(`[data-agent="${name}"]`);
    const status = document.querySelector(`[data-agent-status="${name}"]`);

    if (card) {
      card.dataset.state = "waiting";
    }

    if (status) {
      status.textContent = "Waiting";
    }
  }
}

function updateAgent(payload) {
  const card = document.querySelector(`[data-agent="${payload.stage}"]`);
  const status = document.querySelector(
    `[data-agent-status="${payload.stage}"]`
  );

  if (!card || !status) {
    return;
  }

  card.dataset.state = payload.state || "waiting";

  if (payload.state === "running") {
    status.textContent = "Running";
  } else if (payload.state === "passed") {
    const count = Number(payload.finding_count) || 0;
    status.textContent = `Complete · ${count} finding${count === 1 ? "" : "s"}`;
  } else if (payload.state === "skipped") {
    status.textContent = "Skipped";
  } else if (payload.state === "failed") {
    status.textContent = "Failed";
  } else {
    status.textContent = "Waiting";
  }
}

function downloadBlob(contents, filename, contentType) {
  const blob = new Blob([contents], { type: contentType });
  const objectUrl = URL.createObjectURL(blob);
  const link = document.createElement("a");

  link.href = objectUrl;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();

  window.setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
}

function handleScanEvent(payload) {
  if (payload.type === "status") {
    updateProgress(payload.message, payload.progress);
    addActivity(payload.message);
    return;
  }

  if (payload.type === "stage") {
    updateAgent(payload);
    updateProgress(payload.message, payload.progress);
    addActivity(payload.message);
    return;
  }

  if (payload.type === "error") {
    if (payload.stage) {
      updateAgent({
        stage: payload.stage,
        state: "failed",
      });
    }

    updateProgress(
      payload.message,
      Number(progressTrack.getAttribute("aria-valuenow"))
    );
    addActivity(payload.message);
    return;
  }

  if (payload.type === "complete") {
    latestFindings = Array.isArray(payload.findings) ? payload.findings : [];

    updateProgress(payload.message, 100);
    addActivity(payload.message);

    downloadReportButton.disabled = false;
    downloadProjectButton.disabled =
      activeSource !== "zip" || !selectedZip;
  }
}

async function readProgressStream(response) {
  if (!response.body) {
    throw new Error("The server did not provide a progress stream.");
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let scanCompleted = false;

  function processBlock(block) {
    const dataLines = block
      .split(/\r?\n/)
      .filter((line) => line.startsWith("data:"))
      .map((line) => line.slice(5).trim());

    if (dataLines.length === 0) {
      return;
    }

    const payload = JSON.parse(dataLines.join("\n"));
    handleScanEvent(payload);

    if (payload.type === "complete") {
      scanCompleted = true;
    }

    if (payload.type === "error") {
      throw new Error(payload.message || "The scan could not be completed.");
    }
  }

  while (true) {
    const { value, done } = await reader.read();

    if (done) {
      break;
    }

    buffer += decoder.decode(value, { stream: true });

    let boundary = buffer.search(/\r?\n\r?\n/);
    while (boundary !== -1) {
      const block = buffer.slice(0, boundary);
      const separator = buffer.match(/\r?\n\r?\n/)[0];
      buffer = buffer.slice(boundary + separator.length);

      processBlock(block);
      boundary = buffer.search(/\r?\n\r?\n/);
    }
  }

  buffer += decoder.decode();
  if (buffer.trim()) {
    processBlock(buffer);
  }

  if (!scanCompleted) {
    throw new Error("The progress stream ended before the scan completed.");
  }
}

async function getResponseError(response) {
  try {
    const payload = await response.json();
    if (typeof payload.detail === "string") {
      return payload.detail;
    }
  } catch {
    // Use a general message if the response body is not JSON.
  }

  return `The server returned an error (${response.status}).`;
}

function beginScan(source, message) {
  scanInProgress = true;
  activeSource = source;
  latestFindings = [];

  scanZipButton.disabled = true;
  repositoryButton.disabled = true;
  downloadReportButton.disabled = true;
  downloadProjectButton.disabled = true;

  resetAgentCards();
  activityLog.replaceChildren();

  updateProgress(message, 0);
  addActivity("Starting a new scan.");
}

function finishScan() {
  scanInProgress = false;
  scanZipButton.disabled = !selectedZip;
  repositoryButton.disabled = false;
}

async function startZipScan() {
  if (!selectedZip || scanInProgress) {
    return;
  }

  beginScan("zip", "Uploading project ZIP...");

  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: {
        "Content-Type": "application/zip",
      },
      body: selectedZip,
    });

    if (!response.ok) {
      throw new Error(await getResponseError(response));
    }

    await readProgressStream(response);
  } catch (error) {
    const message =
      error instanceof Error
        ? error.message
        : "The scan could not be completed.";

    updateProgress(
      `Scan stopped: ${message}`,
      progressTrack.getAttribute("aria-valuenow")
    );
    addActivity(`Scan stopped: ${message}`);
  } finally {
    finishScan();
  }
}

async function startRepositoryScan(event) {
  event.preventDefault();

  if (scanInProgress || !repositoryForm.reportValidity()) {
    return;
  }

  const repositoryUrl = repositoryUrlInput.value.trim();
  let githubToken = githubTokenInput.value;
  githubTokenInput.value = "";

  let requestBody = JSON.stringify({
    repository_url: repositoryUrl,
    github_token: githubToken || null,
  });
  githubToken = "";

  beginScan("repository", "Connecting to GitHub...");

  try {
    const pendingResponse = fetch("/api/scan/repository", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: requestBody,
    });

    requestBody = "";

    const response = await pendingResponse;

    if (!response.ok) {
      throw new Error(await getResponseError(response));
    }

    await readProgressStream(response);
  } catch (error) {
    const message =
      error instanceof Error
        ? error.message
        : "The repository scan could not be completed.";

    updateProgress(
      `Scan stopped: ${message}`,
      progressTrack.getAttribute("aria-valuenow")
    );
    addActivity(`Scan stopped: ${message}`);
  } finally {
    githubToken = "";
    requestBody = "";
    githubTokenInput.value = "";
    githubTokenInput.closest("details")?.removeAttribute("open");
    finishScan();
  }
}

zipInput.addEventListener("change", () => {
  selectedZip =
    zipInput.files && zipInput.files.length > 0
      ? zipInput.files[0]
      : null;

  if (selectedZip && !selectedZip.name.toLowerCase().endsWith(".zip")) {
    selectedZip = null;
    zipInput.value = "";
    zipFileName.textContent = "Please choose a .zip file";
    scanZipButton.disabled = true;
    return;
  }

  zipFileName.textContent = selectedZip
    ? selectedZip.name
    : "No file selected";

  scanZipButton.disabled = !selectedZip || scanInProgress;
});

scanZipButton.addEventListener("click", startZipScan);
repositoryForm.addEventListener("submit", startRepositoryScan);

downloadReportButton.addEventListener("click", () => {
  if (downloadReportButton.disabled) {
    return;
  }

  const report = {
    application: "DevSecOps Auditor",
    generated_at: new Date().toISOString(),
    finding_count: latestFindings.length,
    findings: latestFindings,
  };

  downloadBlob(
    JSON.stringify(report, null, 2),
    "devsecops-audit-report.json",
    "application/json"
  );
});

downloadProjectButton.addEventListener("click", () => {
  if (
    downloadProjectButton.disabled ||
    activeSource !== "zip" ||
    !selectedZip
  ) {
    return;
  }

  const objectUrl = URL.createObjectURL(selectedZip);
  const link = document.createElement("a");

  link.href = objectUrl;
  link.download = selectedZip.name;
  document.body.appendChild(link);
  link.click();
  link.remove();

  window.setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
});
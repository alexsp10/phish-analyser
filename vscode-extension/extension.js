// PhishCheck for VS Code.
//
// Adds a "PhishCheck" status-bar button, a "Check with PhishCheck" button on .eml/.mbox
// files, and a panel with the drag-and-drop UI. The analysis itself is done by the
// phishcheck Python package, started as `python -m phishcheck --json <file>`:
// no server, no network, and the file is never opened or executed.
"use strict";

const vscode = require("vscode");
const cp = require("child_process");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");

const MAX_UPLOAD = 25 * 1024 * 1024;

let panel; // the single PhishCheck panel, if open
let ready = false; // has the panel's script loaded?
let queue = []; // messages waiting for the panel to be ready

function activate(context) {
  const status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  status.text = "$(shield) PhishCheck";
  status.tooltip = "Check an email for phishing";
  status.command = "phishcheck.open";
  status.show();

  context.subscriptions.push(
    status,
    vscode.commands.registerCommand("phishcheck.open", () => {
      openPanel(context);
    }),
    vscode.commands.registerCommand("phishcheck.analyseFile", async (uri) => {
      let target = uri instanceof vscode.Uri ? uri : undefined;
      if (!target && vscode.window.activeTextEditor) target = vscode.window.activeTextEditor.document.uri;
      if (!target || target.scheme !== "file" || !/\.(eml|mbox)$/i.test(target.fsPath)) {
        target = await pickFile();
        if (!target) return;
      }
      openPanel(context);
      await analyseAndShow(target.fsPath, path.basename(target.fsPath));
    })
  );
}

function deactivate() {}

// --------------------------------------------------------------------------- panel

function openPanel(context) {
  if (panel) {
    panel.reveal();
    return panel;
  }
  ready = false;
  queue = [];
  panel = vscode.window.createWebviewPanel("phishcheck", "PhishCheck", vscode.ViewColumn.Active, {
    enableScripts: true,
    retainContextWhenHidden: true,
    localResourceRoots: [],
  });
  panel.webview.html = buildHtml(context);
  panel.onDidDispose(
    () => {
      panel = undefined;
      ready = false;
      queue = [];
    },
    null,
    context.subscriptions
  );
  panel.webview.onDidReceiveMessage((message) => handleMessage(message), null, context.subscriptions);
  return panel;
}

function post(message) {
  if (!panel) return;
  if (ready) panel.webview.postMessage(message);
  else queue.push(message);
}

function buildHtml(context) {
  const nonce = crypto.randomBytes(16).toString("base64");
  // Strict CSP: only our own inline script (by nonce) and inline styles; no network access at all.
  const csp =
    '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; ' +
    "style-src 'unsafe-inline'; img-src data:; script-src 'nonce-" +
    nonce +
    "';\">";
  const template = fs.readFileSync(path.join(context.extensionPath, "media", "ui.html"), "utf8");
  return template
    .split("<!--CSP-->").join(csp)
    .split("__NONCE__").join(nonce)
    .split("__TOKEN__").join("")
    .split("__VERSION__").join(String(context.extension.packageJSON.version))
    .split("__MAX_UPLOAD__").join(String(MAX_UPLOAD));
}

async function handleMessage(message) {
  if (!message || typeof message !== "object") return;

  if (message.type === "ready") {
    ready = true;
    const waiting = queue;
    queue = [];
    waiting.forEach((m) => panel && panel.webview.postMessage(m));
    return;
  }

  if (message.type === "pick") {
    const uri = await pickFile();
    if (uri) await analyseAndShow(uri.fsPath, path.basename(uri.fsPath));
    return;
  }

  if (message.type === "analyse") {
    // A file dropped onto the panel: the webview sends its bytes as base64.
    const id = message.id;
    const name = String(message.name || "email.eml");
    let temp;
    try {
      const data = Buffer.from(String(message.data || ""), "base64");
      if (!data.length) throw new Error("That file is empty.");
      if (data.length > MAX_UPLOAD) throw new Error("That file is larger than 25 MB.");
      const ext = /\.mbox$/i.test(name) ? ".mbox" : ".eml";
      temp = path.join(os.tmpdir(), "phishcheck-" + crypto.randomBytes(8).toString("hex") + ext);
      fs.writeFileSync(temp, data, { mode: 0o600 });
      const results = await runPhishcheck(temp);
      relabel(results, name);
      post({ type: "result", id, results });
    } catch (err) {
      post({ type: "result", id, error: (err && err.message) || String(err) });
    } finally {
      if (temp) fs.rmSync(temp, { force: true });
    }
  }
}

async function analyseAndShow(filePath, label) {
  post({ type: "busy", on: true });
  try {
    const results = await runPhishcheck(filePath);
    relabel(results, label);
    post({ type: "show", results });
  } catch (err) {
    post({ type: "error", error: (err && err.message) || String(err) });
  }
}

function relabel(results, label) {
  results.forEach((result, index) => {
    result.source = results.length > 1 ? label + " #" + (index + 1) : label;
  });
}

async function pickFile() {
  const picked = await vscode.window.showOpenDialog({
    canSelectMany: false,
    openLabel: "Check with PhishCheck",
    filters: { "Email files": ["eml", "mbox"] },
  });
  return picked && picked[0];
}

// --------------------------------------------------------------------------- python

function resolvePython() {
  const configured = vscode.workspace.getConfiguration("phishcheck").get("pythonPath");
  if (configured) return configured;
  for (const folder of vscode.workspace.workspaceFolders || []) {
    for (const parts of [[".venv", "Scripts", "python.exe"], [".venv", "bin", "python"]]) {
      const candidate = path.join(folder.uri.fsPath, ...parts);
      if (fs.existsSync(candidate)) return candidate;
    }
  }
  return process.platform === "win32" ? "python" : "python3";
}

function runPhishcheck(file) {
  const python = resolvePython();
  const args = ["-m", "phishcheck", "--json", file];
  const brands = vscode.workspace.getConfiguration("phishcheck").get("brandsFile");
  if (brands) args.push("--brands", brands);

  return new Promise((resolve, reject) => {
    // execFile (no shell): file names can't be interpreted as commands.
    cp.execFile(
      python,
      args,
      {
        encoding: "utf8",
        maxBuffer: 64 * 1024 * 1024,
        timeout: 120000,
        windowsHide: true,
        env: Object.assign({}, process.env, { PYTHONIOENCODING: "utf-8", PYTHONUTF8: "1" }),
      },
      (error, stdout, stderr) => {
        if (error && !stdout) {
          if (error.code === "ENOENT") {
            reject(new Error('Python was not found at "' + python + '". Set "phishcheck.pythonPath" in VS Code settings.'));
          } else if (/No module named phishcheck/.test(stderr || "")) {
            reject(new Error("PhishCheck isn't installed for " + python + '. Set "phishcheck.pythonPath" to the phish-analyser .venv Python.'));
          } else {
            const lines = String(stderr || error.message).trim().split(/\r?\n/);
            reject(new Error(lines[lines.length - 1] || "PhishCheck failed."));
          }
          return;
        }
        let data;
        try {
          data = JSON.parse(stdout);
        } catch (parseError) {
          reject(new Error("Unexpected output from PhishCheck: " + String(stderr || stdout).slice(0, 300)));
          return;
        }
        if (!Array.isArray(data) || !data.length) {
          reject(new Error("No emails were found in that file."));
          return;
        }
        resolve(data);
      }
    );
  });
}

module.exports = { activate, deactivate };

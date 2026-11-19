# PhishCheck for VS Code

Check Gmail `.eml` files (and Google Takeout `.mbox` archives) for phishing without leaving VS Code.

- **🛡 PhishCheck** in the status bar opens the panel: drop an email on it (hold **Shift** while dropping) or click **Choose file**.
- Open or right-click an `.eml` file and click **Check with PhishCheck** (the shield button at the top right of the editor).
- The result pops up with a risk score, SPF/DKIM/DMARC status, the reasons, and what to do next.

The analysis is done by the local `phishcheck` Python package (`python -m phishcheck --json`). Nothing is sent over the network, links are never opened, and attachments are never run.

## Settings

| Setting | Purpose |
| --- | --- |
| `phishcheck.pythonPath` | Python that has phishcheck installed. Set automatically when the extension is built from the project. |
| `phishcheck.brandsFile` | Optional JSON of extra brands to protect (e.g. your bank). |

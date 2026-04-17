# PwnDoc Importer

An [Obsidian](https://obsidian.md) plugin that imports vulnerabilities from a [PwnDoc](https://github.com/pwndoc/pwndoc) instance — either from a local CSV export or directly via the PwnDoc API — and automatically creates structured notes in your vault.

## Features

- Import vulnerabilities from a PwnDoc CSV export via fuzzy-search modal
- Fetch vulnerabilities directly from the PwnDoc API without a pre-exported file
- API credentials can be saved in plugin settings or entered in a popup at import time
- Optionally save the fetched API data as a local CSV for future offline use, with a configurable default output folder
- Automatically calculate CVSS 3.1 scores and severity ratings
- Convert HTML-formatted PwnDoc fields to clean plain text
- Generate pre-structured notes with YAML frontmatter (severity, platform, CVSS data, OWASP category, CWE)
- Automatically fetch custom field definitions from the API and append all non-empty custom fields as a **Custom Fields** section at the end of the note, using human-readable labels (`displaySub`)
- Filter vulnerabilities by locale (`EN-en`, `IT-it`, or all)
- Choose between **VT** (Vulnerability Ticket) or **M** (Mobile) note prefixes
- Auto-number notes sequentially (`VT-01`, `VT-02`, …)
- Select the target vault folder interactively on each import

## Requirements

- Obsidian 1.0.0 or later
- Desktop only (not supported on mobile)

## Installation

1. Download or clone this repository into your vault's plugin folder:
   ```
   <your-vault>/.obsidian/plugins/pwndoc-importer/
   ```
2. Ensure the folder contains `manifest.json` and `main.js`.
3. In Obsidian, go to **Settings → Community plugins**, disable Safe Mode, and enable **PwnDoc Importer**.

## Configuration

Open **Settings → PwnDoc Importer** to configure the plugin.

### General

| Setting | Default | Description |
|---|---|---|
| **CSV file path** | *(empty)* | Absolute or vault-relative path to a PwnDoc vulnerabilities CSV export |
| **Locale filter** | `EN-en` | Filter vulnerabilities by language (`EN-en`, `IT-it`, or `All`) |

### Custom field IDs

| Setting | Default | Description |
|---|---|---|
| **OWASP field column** | `cf_62d92f1597c7c5001833273f` | Field ID for OWASP category (matches the `_id` in PwnDoc custom fields) |
| **CWE field column** | `cf_63ab317fafe66f0011b89881` | Field ID for CWE identifier |

These values must match the `_id` of the corresponding custom fields in your PwnDoc instance.

### API credentials

| Setting | Description |
|---|---|
| **PwnDoc URL** | Base URL of the PwnDoc instance (e.g. `https://localhost:8443`) |
| **Username** | PwnDoc username |
| **Password** | PwnDoc password — stored in plain text in the plugin data file |
| **Ignore SSL certificate errors** | Enable for self-signed certificates |

If any credential field is left blank, the plugin will prompt for credentials at import time. Credentials can also be saved from the import popup by checking **Save credentials in plugin settings**.

### CSV output

| Setting | Description |
|---|---|
| **Default CSV output folder** | Absolute path to the folder where `vulnerabilities.csv` will be saved after an API fetch. Leave blank to be prompted each time. |

### Debug

| Setting | Default | Description |
|---|---|---|
| **Debug mode** | `off` | When enabled, logs detailed information to the browser console during API imports. Open the developer tools with `Ctrl+Shift+I` and filter by `[PwnDoc Importer]` in the Console tab. |

## Usage

Two import commands are available from the command palette (`Ctrl+P` / `Cmd+P`).

### From CSV

1. Run **Import vulnerability from CSV**.
2. Search for the vulnerability using the fuzzy-search modal (shows title, locale, category, and priority).
3. Choose the note prefix: **VT** (Vulnerability Ticket) or **M** (Mobile).
4. Choose the target vault folder (current folder or custom path).
5. The note is created and opened automatically.

### From PwnDoc API

1. Run **Fetch and import vulnerability from PwnDoc API**.
2. A **credentials popup** appears, pre-filled with any values saved in settings. Adjust if needed, enable **Ignore SSL** for self-signed certs, and optionally check **Save credentials in plugin settings** to persist them.
3. The plugin logs in, fetches all vulnerabilities and custom field definitions in parallel, then shows a **CSV output popup** pre-filled with the default output folder from settings:
   - Confirm the folder path to save the fetched data as `vulnerabilities.csv` for future offline use.
   - Click **Skip** to import without saving.
4. The locale filter from settings is applied, then the usual fuzzy-search → prefix → folder → note flow continues.

## Generated Note Structure

Notes are named `<PREFIX>-<NN> - <Title>.md` (e.g. `VT-03 - SQL Injection.md`) and contain:

**YAML frontmatter**
```yaml
severity: CRITICAL
platform: WEB
cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
cvss_link: "https://www.first.org/cvss/calculator/3-1#CVSS:3.1/..."
cvss_score: 9.8
cvss_severity: CRITICAL
status: "DRAFT"
pwndoc: true
pwndoc_id: "<original_pwndoc_id>"
locale: "EN-en"
category: "WAPT"
assets: "INSERT_ASSET"
```

**Content sections**
- Metadata table (Severity, CVSS 3.1 vector + score, OWASP category, CWE)
- Description
- Impact
- Evidence *(blank — to be filled during the assessment)*
- Assets *(blank — to be filled during the assessment)*
- Remediation
- References *(included only when present in the source data)*
- Custom Fields *(included only when the vulnerability has non-empty custom fields beyond OWASP and CWE; each field is rendered as a bold label followed by its plain-text value)*

**Custom field resolution** — when importing via API, the plugin calls `GET /api/data/custom_fields` in parallel with the vulnerability fetch and builds a map of `_id → displaySub`. This label is used as the column name in the saved CSV and as the section header in the note. When importing from a CSV saved without API metadata, the raw `cf_<id>` key is used as fallback.

Platform is inferred automatically from the PwnDoc category:
- `WAPT` → `WEB`
- `Android` → `Android`
- `iOS` → `iOS`
- `Mobile` / anything else → `Mobile`

## CSV Format

The plugin expects a CSV with (at minimum) the following columns. This is the format produced by both the PwnDoc API import (when saving) and any companion export script.

| Column | Description |
|---|---|
| `id` | PwnDoc vulnerability ID |
| `title` | Vulnerability title |
| `locale` | Language code (e.g. `EN-en`) |
| `category` | Category (e.g. `WAPT`, `Android`) |
| `priority` | Priority level |
| `cvssv3` | CVSS 3.1 vector string |
| `description` | HTML-formatted description |
| `observation` | HTML-formatted impact/observation |
| `remediation` | HTML-formatted remediation steps |
| `references` | Reference links |
| *custom field columns* | Named after the `displaySub` label from PwnDoc (or `cf_<id>` if label is unavailable) |

## Author

davide.caputo

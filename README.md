# PwnDoc Importer

An [Obsidian](https://obsidian.md) plugin that imports vulnerabilities from a [PwnDoc](https://github.com/pwndoc/pwndoc) instance — either from a local CSV export or directly via the PwnDoc API — and automatically creates structured notes in your vault.

## Features

- Import vulnerabilities from a PwnDoc CSV export via fuzzy-search modal
- Fetch vulnerabilities directly from the PwnDoc API without a pre-exported file
- Credentials for API access are entered in a popup and **never saved** to the vault
- Optionally save the fetched API data as a local CSV for future offline use
- Automatically calculate CVSS 3.1 scores and severity ratings
- Convert HTML-formatted PwnDoc fields to clean plain text
- Generate pre-structured notes with YAML frontmatter (severity, platform, CVSS data, OWASP category, CWE)
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

| Setting | Default | Description |
|---|---|---|
| **CSV file path** | *(empty)* | Absolute or vault-relative path to a PwnDoc vulnerabilities CSV export |
| **Locale filter** | `EN-en` | Filter vulnerabilities by language (`EN-en`, `IT-it`, or `All`) |
| **OWASP field column ID** | `cf_62d92f1597c7c5001833273f` | CSV column ID containing OWASP category data |
| **CWE field column ID** | `cf_63ab317fafe66f0011b89881` | CSV column ID containing CWE identifier data |

The OWASP and CWE column IDs match the custom field IDs in your PwnDoc instance. Check the CSV export headers if the defaults do not match.

> API credentials (URL, username, password) are **not stored in settings**. They are entered in a popup each time you run the API import command.

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
2. A **credentials popup** appears — enter the PwnDoc URL, username, password, and optionally enable "Ignore SSL certificate errors" for self-signed certs. Nothing is saved to disk.
3. The plugin logs in, fetches all vulnerabilities, and shows a **CSV output popup**:
   - Enter an absolute folder path (e.g. `C:/tools/pwndoc` or `/home/user/pwndoc`) to save the fetched data as `vulnerabilities.csv` for future offline use.
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

Platform is inferred automatically from the PwnDoc category:
- `WAPT` → `WEB`
- `Android` → `Android`
- `iOS` → `iOS`
- `Mobile` / anything else → `Mobile`

## CSV Format

The plugin expects a CSV with (at minimum) the following columns. This is the format produced by both the PwnDoc API import (when saving) and the companion `pwndoc_export.py` script.

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
| *custom field columns* | OWASP and CWE values (column IDs set in plugin settings) |

## Author

davide.caputo

'use strict';

const { Plugin, PluginSettingTab, Setting, FuzzySuggestModal, SuggestModal, Modal, Notice, normalizePath } = require('obsidian');

// ── CSV Parser ────────────────────────────────────────────────────────────────
function parseCSV(text) {
    text = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
    const records = [];
    let i = 0;

    while (i <= text.length) {
        const fields = [];
        while (true) {
            let field = '';
            if (i < text.length && text[i] === '"') {
                i++;
                while (i < text.length) {
                    if (text[i] === '"') {
                        if (i + 1 < text.length && text[i + 1] === '"') { field += '"'; i += 2; }
                        else { i++; break; }
                    } else { field += text[i++]; }
                }
            } else {
                while (i < text.length && text[i] !== ',' && text[i] !== '\n') field += text[i++];
            }
            fields.push(field);
            if (i < text.length && text[i] === ',') { i++; continue; }
            break;
        }
        if (i < text.length && text[i] === '\n') i++;
        if (fields.length > 0 && !(fields.length === 1 && fields[0] === '')) records.push(fields);
        if (i >= text.length) break;
    }

    if (records.length < 2) return [];
    const headers = records[0].map(h => h.trim());
    return records.slice(1).map(fields => {
        const row = {};
        headers.forEach((h, idx) => { row[h] = fields[idx] ?? ''; });
        return row;
    });
}

// ── HTML → plain text ─────────────────────────────────────────────────────────
function stripHtml(html) {
    if (!html) return '';
    return html
        .replace(/<br\s*\/?>/gi, '\n')
        .replace(/<\/?(p|div|li|h[1-6])[^>]*>/gi, '\n')
        .replace(/<ul[^>]*>|<\/ul>/gi, '\n')
        .replace(/<ol[^>]*>|<\/ol>/gi, '\n')
        .replace(/<[^>]+>/g, '')
        .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&')
        .replace(/&nbsp;/g, ' ').replace(/&#39;/g, "'").replace(/&quot;/g, '"')
        .replace(/\n{3,}/g, '\n\n')
        .trim();
}

// ── CVSS 3.1 score calculator ─────────────────────────────────────────────────
function computeCVSS31(vector) {
    if (!vector || !vector.startsWith('CVSS:3.1/')) return { score: '0.0', severity: 'INFO' };

    const parts = {};
    vector.replace('CVSS:3.1/', '').split('/').forEach(p => {
        const [k, v] = p.split(':');
        parts[k] = v;
    });

    const W = {
        AV:  { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
        AC:  { L: 0.77, H: 0.44 },
        PR:  { U: { N: 0.85, L: 0.62, H: 0.27 }, C: { N: 0.85, L: 0.68, H: 0.50 } },
        UI:  { N: 0.85, R: 0.62 },
        CIA: { N: 0.0,  L: 0.22, H: 0.56 },
    };

    const { AV, AC, PR, UI, S, C, I, A } = parts;
    if (!AV || !AC || !PR || !UI || !S || !C || !I || !A) return { score: '0.0', severity: 'INFO' };

    const iss = 1 - (1 - W.CIA[C]) * (1 - W.CIA[I]) * (1 - W.CIA[A]);
    const impact = S === 'U'
        ? 6.42 * iss
        : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
    const exploit = 8.22 * W.AV[AV] * W.AC[AC] * W.PR[S][PR] * W.UI[UI];

    let base = 0;
    if (impact > 0) {
        base = S === 'U'
            ? Math.min(impact + exploit, 10)
            : Math.min(1.08 * (impact + exploit), 10);
    }

    const score = (Math.ceil(base * 10) / 10).toFixed(1);
    const n = parseFloat(score);
    const severity = n === 0.0 ? 'INFO' : n <= 3.9 ? 'LOW' : n <= 6.9 ? 'MEDIUM' : n <= 8.9 ? 'HIGH' : 'CRITICAL';
    return { score, severity };
}

// ── Read file (absolute path or vault-relative) ───────────────────────────────
async function readFilePath(app, filePath) {
    if (/^([A-Za-z]:[\\/]|\/)/.test(filePath)) {
        return require('fs').readFileSync(filePath, 'utf8');
    }
    return await app.vault.adapter.read(normalizePath(filePath));
}

// ── Settings ──────────────────────────────────────────────────────────────────
const DEFAULT_SETTINGS = {
    csvPath: '',
    locale: 'EN-en',
    owaspFieldId: 'cf_62d92f1597c7c5001833273f',
    cweFieldId:   'cf_63ab317fafe66f0011b89881',
};

// ── Modal: fuzzy search over vuln list ────────────────────────────────────────
class VulnSearchModal extends FuzzySuggestModal {
    constructor(app, vulns, onChoose) {
        super(app);
        this.vulns = vulns;
        this.onChoose = onChoose;
        this.setPlaceholder('Type to search vulnerability name...');
    }
    getItems() { return this.vulns; }
    getItemText(item) { return `${item.title || item.id || 'Unknown'} ${item.locale || ''}`; }
    renderSuggestion(item, el) {
        const v = item.item;
        el.createEl('div', { text: v.title || 'Unknown', cls: 'pwndoc-title' });
        el.createEl('small', {
            text: [v.locale, v.category, v.priority].filter(Boolean).join(' · '),
            cls: 'pwndoc-meta',
        });
    }
    onChooseItem(item) { this.onChoose(item); }
}

// ── Modal: choose VT or M prefix ─────────────────────────────────────────────
class PrefixModal extends SuggestModal {
    constructor(app, onChoose) {
        super(app);
        this.onChoose = onChoose;
        this.setPlaceholder('Select note type...');
    }
    getSuggestions(query) {
        const options = [
            { label: 'VT — Vulnerability Ticket', value: 'VT' },
            { label: 'M  — Mobile',               value: 'M'  },
        ];
        return options.filter(o => o.label.toLowerCase().includes(query.toLowerCase()));
    }
    renderSuggestion(item, el) {
        el.createEl('div', { text: item.label });
    }
    onChooseSuggestion(item) { this.onChoose(item.value); }
}

// ── Modal: choose target folder ───────────────────────────────────────────────
class FolderModal extends Modal {
    /**
     * @param {import('obsidian').App} app
     * @param {string} currentFolder   - path of the active file's parent
     * @param {function(string)} onChoose
     */
    constructor(app, currentFolder, onChoose) {
        super(app);
        this.currentFolder = currentFolder;
        this.onChoose = onChoose;
    }

    onOpen() {
        const { contentEl } = this;
        contentEl.empty();
        contentEl.createEl('h3', { text: 'Where should the note be created?' });

        // Option 1 — current folder button
        const currentLabel = this.currentFolder || '/ (vault root)';
        const btn = contentEl.createEl('button', {
            text: `Current folder: ${currentLabel}`,
            cls: 'mod-cta pwndoc-folder-btn',
        });
        btn.style.cssText = 'width:100%;margin-bottom:12px;';
        btn.onclick = () => { this.close(); this.onChoose(this.currentFolder); };

        // Option 2 — custom folder input
        contentEl.createEl('p', { text: 'Or type a custom vault folder path:' });
        const input = contentEl.createEl('input', { type: 'text', cls: 'pwndoc-folder-input' });
        input.placeholder = 'client/project/vulns';
        input.style.cssText = 'width:100%;margin-bottom:8px;';

        const confirm = contentEl.createEl('button', { text: 'Use this folder' });
        confirm.style.cssText = 'width:100%;';
        confirm.onclick = () => {
            const val = input.value.trim();
            if (!val) { new Notice('Please enter a folder path.'); return; }
            this.close();
            this.onChoose(val);
        };

        // Allow Enter key in the input to confirm
        input.addEventListener('keydown', e => {
            if (e.key === 'Enter') confirm.click();
        });

        // Focus the button so keyboard users can immediately press Enter or Tab
        btn.focus();
    }

    onClose() { this.contentEl.empty(); }
}

// ── Settings tab ──────────────────────────────────────────────────────────────
class PwnDocSettingTab extends PluginSettingTab {
    constructor(app, plugin) {
        super(app, plugin);
        this.plugin = plugin;
    }

    display() {
        const { containerEl } = this;
        containerEl.empty();
        containerEl.createEl('h2', { text: 'PwnDoc Importer' });

        new Setting(containerEl)
            .setName('CSV file path')
            .setDesc('Absolute path or vault-relative path to vulnerabilities.csv')
            .addText(t => t
                .setPlaceholder('C:/tools/pwndoc-api/vulnerabilities.csv')
                .setValue(this.plugin.settings.csvPath)
                .onChange(async v => { this.plugin.settings.csvPath = v.trim(); await this.plugin.saveSettings(); }));

        new Setting(containerEl)
            .setName('Locale filter')
            .setDesc('Only show vulnerabilities with this locale in the search list')
            .addDropdown(d => d
                .addOption('EN-en', 'EN-en (English)')
                .addOption('IT-it', 'IT-it (Italian)')
                .addOption('', 'All locales')
                .setValue(this.plugin.settings.locale)
                .onChange(async v => { this.plugin.settings.locale = v; await this.plugin.saveSettings(); }));

        containerEl.createEl('h3', { text: 'Custom field IDs' });
        containerEl.createEl('p', {
            text: 'cf_<objectId> column names in the CSV for OWASP and CWE values.',
            cls: 'setting-item-description',
        });

        new Setting(containerEl)
            .setName('OWASP field column')
            .addText(t => t
                .setValue(this.plugin.settings.owaspFieldId)
                .onChange(async v => { this.plugin.settings.owaspFieldId = v.trim(); await this.plugin.saveSettings(); }));

        new Setting(containerEl)
            .setName('CWE field column')
            .addText(t => t
                .setValue(this.plugin.settings.cweFieldId)
                .onChange(async v => { this.plugin.settings.cweFieldId = v.trim(); await this.plugin.saveSettings(); }));
    }
}

// ── Plugin ────────────────────────────────────────────────────────────────────
class PwnDocImporterPlugin extends Plugin {
    async onload() {
        await this.loadSettings();
        this.addSettingTab(new PwnDocSettingTab(this.app, this));
        this.addCommand({
            id: 'import-vuln-from-csv',
            name: 'Import vulnerability from CSV',
            callback: () => this.openSearchModal(),
        });
    }

    async loadSettings() {
        this.settings = Object.assign({}, DEFAULT_SETTINGS, await this.loadData());
    }
    async saveSettings() { await this.saveData(this.settings); }

    // Step 1 — load CSV and open vuln search
    async openSearchModal() {
        const { csvPath, locale } = this.settings;
        if (!csvPath) {
            new Notice('PwnDoc Importer: set the CSV path in Settings first.');
            return;
        }

        let text;
        try { text = await readFilePath(this.app, csvPath); }
        catch (e) { new Notice(`PwnDoc Importer: cannot read CSV — ${e.message}`); return; }

        let rows = parseCSV(text);
        if (rows.length === 0) {
            new Notice('PwnDoc Importer: CSV is empty or could not be parsed.');
            return;
        }

        if (locale) {
            const filtered = rows.filter(r => r.locale === locale);
            if (filtered.length > 0) rows = filtered;
        }

        if (rows.length === 0) {
            new Notice(`PwnDoc Importer: no vulnerabilities found for locale "${locale}".`);
            return;
        }

        new VulnSearchModal(this.app, rows, vuln => this.askPrefix(vuln)).open();
    }

    // Step 2 — ask VT or M
    askPrefix(vuln) {
        new PrefixModal(this.app, prefix => this.askFolder(vuln, prefix)).open();
    }

    // Step 3 — ask current folder or custom
    askFolder(vuln, prefix) {
        const activeFile = this.app.workspace.getActiveFile();
        const currentFolder = activeFile?.parent?.path ?? '';
        new FolderModal(this.app, currentFolder, folder => this.createVulnNote(vuln, prefix, folder)).open();
    }

    // Step 4 — create the note
    async createVulnNote(vuln, prefix, folder) {
        // Next sequential number for the chosen prefix inside the target folder
        const allFiles = this.app.vault.getMarkdownFiles();
        const folderFiles = folder
            ? allFiles.filter(f => f.parent?.path === folder)
            : allFiles.filter(f => !f.parent || f.parent.path === '/');

        const existing = folderFiles
            .map(f => { const m = f.basename.match(new RegExp(`^${prefix}-(\\d+)`)); return m ? parseInt(m[1]) : 0; })
            .filter(n => n > 0);
        const nextNum = existing.length > 0 ? Math.max(...existing) + 1 : 1;
        const num = String(nextNum).padStart(2, '0');

        // CVSS
        const { score: cvssScore, severity: cvssSeverity } = computeCVSS31(vuln.cvssv3);
        const cvssVector = vuln.cvssv3 || 'N/A';
        const cvssLink = cvssVector !== 'N/A' ? `https://www.first.org/cvss/calculator/3-1#${cvssVector}` : '';

        // Platform from category
        const platformMap = { WAPT: 'WEB', Android: 'Android', iOS: 'iOS', Mobile: 'Android' };
        const platform = prefix === 'M'
            ? (platformMap[vuln.category] || 'Android')
            : (platformMap[vuln.category] || 'WEB');

        // OWASP + CWE
        const owasp = vuln[this.settings.owaspFieldId] || '';
        const cwe   = vuln[this.settings.cweFieldId]   || '';

        // Content sections (HTML stripped)
        const description  = stripHtml(vuln.description);
        const observation  = stripHtml(vuln.observation);
        const remediation  = stripHtml(vuln.remediation);
        const references   = vuln.references || '';

        const title    = (vuln.title || 'Untitled').replace(/[\\/:*?"<>|]/g, '-');
        const noteName = `${prefix}-${num} - ${title}`;
        const filePath = folder ? `${folder}/${noteName}.md` : `${noteName}.md`;

        const content = [
            '---',
            `severity: ${cvssSeverity}`,
            `platform: ${platform}`,
            `cvss_vector: "${cvssVector}"`,
            `cvss_link: "${cvssLink}"`,
            `cvss_score: ${parseFloat(cvssScore)}`,
            `cvss_severity: ${cvssSeverity}`,
            `status: "DRAFT"`,
            `pwndoc: true`,
            `pwndoc_id: "${vuln.id}"`,
            `locale: "${vuln.locale}"`,
            `category: "${vuln.category}"`,
            `assets: "INSERT_ASSET"`,
            '---',
            '',
            `| **Severity**       | ${cvssSeverity.padEnd(38)} |`,
            `| ------------------ | -------------------------------------- |`,
            `| **CVSS3.1**        | ${cvssVector.padEnd(38)} |`,
            `| **CVSS Score**     | ${(cvssScore + ' - (' + cvssSeverity + ')').padEnd(38)} |`,
            `| **OWASP Category** | ${owasp.padEnd(38)} |`,
            `| **CWE**            | ${cwe.padEnd(38)} |`,
            '',
            '---',
            '',
            '## Descrizione',
            '',
            description,
            '',
            '## Impatto',
            '',
            observation,
            '',
            '## Evidenza',
            '',
            '',
            '## Assets',
            '',
            '',
            '## Remediation',
            '',
            remediation,
            '',
            ...(references ? ['## References', '', references] : []),
        ].join('\n').trimEnd() + '\n';

        try {
            if (folder && !this.app.vault.getAbstractFileByPath(folder)) {
                await this.app.vault.createFolder(folder);
            }
            const file = await this.app.vault.create(normalizePath(filePath), content);
            await this.app.workspace.getLeaf().openFile(file);
            new Notice(`Created: ${noteName}`);
        } catch (e) {
            new Notice(`PwnDoc Importer: failed to create note — ${e.message}`);
            console.error(e);
        }
    }
}

module.exports = PwnDocImporterPlugin;

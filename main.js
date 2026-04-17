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

// ── PwnDoc API client ─────────────────────────────────────────────────────────
const PRIORITY_MAP_API = { 1: 'Low', 2: 'Medium', 3: 'High', 4: 'Critical' };

function httpsRequest(urlStr, { method = 'GET', headers = {}, body = null, ignoreSsl = false } = {}) {
    return new Promise((resolve, reject) => {
        const https = require('https');
        const url = new URL(urlStr);
        const options = {
            hostname: url.hostname,
            port: url.port || 443,
            path: url.pathname + url.search,
            method,
            headers,
            rejectUnauthorized: !ignoreSsl,
        };
        const req = https.request(options, res => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                if (res.statusCode >= 200 && res.statusCode < 300) resolve(data);
                else reject(new Error(`HTTP ${res.statusCode}: ${data.slice(0, 200)}`));
            });
        });
        req.on('error', reject);
        if (body) req.write(body);
        req.end();
    });
}

async function pwndocLogin(baseUrl, username, password, ignoreSsl) {
    const url = new URL('/api/users/token', baseUrl).toString();
    const body = JSON.stringify({ username, password, totpToken: '' });
    const raw = await httpsRequest(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
        body,
        ignoreSsl,
    });
    const data = JSON.parse(raw);
    const token = data?.datas?.token;
    if (!token) throw new Error('Login failed: no token in response');
    return token;
}

async function pwndocFetchVulns(baseUrl, token, ignoreSsl) {
    const url = new URL('/api/vulnerabilities', baseUrl).toString();
    const raw = await httpsRequest(url, {
        headers: { 'Cookie': `token= JWT ${token}` },
        ignoreSsl,
    });
    const data = JSON.parse(raw);
    return data?.datas || [];
}

async function pwndocFetchCustomFields(baseUrl, token, ignoreSsl, dbg) {
    const url = new URL('/api/data/custom-fields', baseUrl).toString();
    dbg('pwndocFetchCustomFields: GET', url);
    const raw = await httpsRequest(url, {
        headers: { 'Cookie': `token= JWT ${token}` },
        ignoreSsl,
    });
    const data = JSON.parse(raw);
    dbg('pwndocFetchCustomFields: raw datas', data?.datas);
    const map = {};
    for (const cf of (data?.datas || [])) {
        if (cf._id) {
            map[cf._id] = cf.label || cf._id;
            dbg(`  mapped ${cf._id} → "${map[cf._id]}" (label="${cf.label}")`);
        }
    }
    dbg('pwndocFetchCustomFields: final map', map);
    return map;
}

const STANDARD_FIELDS = new Set(['id', 'cvssv3', 'priority', 'category', 'locale', 'title', 'description', 'observation', 'remediation', 'references']);

function flattenVulnsFromApi(vulns, cfLabels = {}) {
    const rows = [];
    for (const vuln of vulns) {
        for (const detail of (vuln.details || [])) {
            const refs = detail.references || [];
            const references = Array.isArray(refs) ? refs.join('; ') : String(refs);
            const row = {
                id:          vuln._id        || '',
                cvssv3:      vuln.cvssv3     || '',
                priority:    PRIORITY_MAP_API[vuln.priority] || String(vuln.priority || ''),
                category:    vuln.category   || '',
                locale:      detail.locale   || '',
                title:       detail.title    || '',
                description: detail.description || '',
                observation: detail.observation || '',
                remediation: detail.remediation || '',
                references,
            };
            for (const cf of (detail.customFields || [])) {
                if (cf.customField) {
                    const key = cfLabels[cf.customField] || `cf_${cf.customField}`;
                    let val = cf.text || '';
                    if (Array.isArray(val)) val = val.join('; ');
                    row[key] = val;
                }
            }
            rows.push(row);
        }
    }
    return rows;
}

// ── Settings ──────────────────────────────────────────────────────────────────
const DEFAULT_SETTINGS = {
    csvPath:         '',
    locale:          'EN-en',
    owaspFieldId:    'cf_62d92f1597c7c5001833273f',
    cweFieldId:      'cf_63ab317fafe66f0011b89881',
    apiUrl:          '',
    apiUsername:     '',
    apiPassword:     '',
    apiIgnoreSsl:    false,
    csvOutputFolder: '',
    debugMode:       false,
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

// ── CSV serialiser ────────────────────────────────────────────────────────────
function rowsToCsv(rows) {
    if (!rows.length) return '';
    const seen = {};
    for (const row of rows) for (const k of Object.keys(row)) seen[k] = true;
    const headers = Object.keys(seen);
    const esc = v => {
        const s = String(v ?? '');
        return (s.includes(',') || s.includes('"') || s.includes('\n') || s.includes('\r'))
            ? '"' + s.replace(/"/g, '""') + '"'
            : s;
    };
    const lines = [headers.map(esc).join(',')];
    for (const row of rows) lines.push(headers.map(h => esc(row[h] ?? '')).join(','));
    return lines.join('\r\n');
}

// ── Modal: PwnDoc API credentials ────────────────────────────────────────────
class ApiCredentialsModal extends Modal {
    constructor(app, settings, onConnect) {
        super(app);
        this.settings  = settings;
        this.onConnect = onConnect; // ({url, username, password, ignoreSsl, save}) => void
    }

    onOpen() {
        const { contentEl } = this;
        contentEl.empty();
        contentEl.createEl('h3', { text: 'Connect to PwnDoc' });

        const mkRow = (label, inputFn) => {
            const wrap = contentEl.createEl('div');
            wrap.style.cssText = 'display:flex;flex-direction:column;margin-bottom:10px;';
            wrap.createEl('label', { text: label }).style.cssText = 'font-size:0.85em;margin-bottom:3px;';
            return inputFn(wrap);
        };

        const mkCheck = (labelText, checked) => {
            const wrap = contentEl.createEl('div');
            wrap.style.cssText = 'display:flex;align-items:center;gap:8px;margin-bottom:10px;';
            const el = wrap.createEl('input', { type: 'checkbox' });
            el.checked = checked;
            wrap.createEl('span', { text: labelText }).style.cssText = 'font-size:0.85em;';
            return el;
        };

        const s = this.settings;

        const urlInput  = mkRow('URL (e.g. https://localhost:8443)', wrap => {
            const el = wrap.createEl('input', { type: 'text' });
            el.placeholder = 'https://localhost:8443';
            el.value = s.apiUrl || '';
            el.style.cssText = 'width:100%;';
            return el;
        });

        const userInput = mkRow('Username', wrap => {
            const el = wrap.createEl('input', { type: 'text' });
            el.value = s.apiUsername || '';
            el.style.cssText = 'width:100%;';
            return el;
        });

        const passInput = mkRow('Password', wrap => {
            const el = wrap.createEl('input', { type: 'password' });
            el.value = s.apiPassword || '';
            el.style.cssText = 'width:100%;';
            return el;
        });

        const sslCheck  = mkCheck('Ignore SSL certificate errors (self-signed certs)', s.apiIgnoreSsl || false);
        const saveCheck = mkCheck('Save credentials in plugin settings', false);

        const btn = contentEl.createEl('button', { text: 'Connect', cls: 'mod-cta' });
        btn.style.cssText = 'width:100%;margin-top:4px;';
        const doConnect = () => {
            const url      = urlInput.value.trim();
            const username = userInput.value.trim();
            const password = passInput.value;
            if (!url)      { new Notice('Please enter the PwnDoc URL.');  return; }
            if (!username) { new Notice('Please enter your username.');    return; }
            if (!password) { new Notice('Please enter your password.');    return; }
            this.close();
            this.onConnect({ url, username, password, ignoreSsl: sslCheck.checked, save: saveCheck.checked });
        };
        btn.onclick = doConnect;
        passInput.addEventListener('keydown', e => { if (e.key === 'Enter') doConnect(); });
        urlInput.focus();
    }

    onClose() { this.contentEl.empty(); }
}

// ── Modal: choose where to save the fetched CSV ───────────────────────────────
class CsvOutputModal extends Modal {
    constructor(app, defaultFolder, onChoose) {
        super(app);
        this.defaultFolder = defaultFolder;
        this.onChoose = onChoose; // (absolutePath | null) => void
    }

    onOpen() {
        const { contentEl } = this;
        contentEl.empty();
        contentEl.createEl('h3', { text: 'Save fetched vulnerabilities as CSV?' });
        contentEl.createEl('p', {
            text: 'Enter an absolute folder path. The file will be saved as vulnerabilities.csv inside it.',
            cls: 'setting-item-description',
        });

        const input = contentEl.createEl('input', { type: 'text' });
        input.placeholder = 'C:/tools/pwndoc  or  /home/user/pwndoc';
        input.value = this.defaultFolder || '';
        input.style.cssText = 'width:100%;margin-bottom:10px;';

        const saveBtn = contentEl.createEl('button', { text: 'Save & Import', cls: 'mod-cta' });
        saveBtn.style.cssText = 'width:100%;margin-bottom:6px;';
        saveBtn.onclick = () => {
            const folder = input.value.trim();
            if (!folder) { new Notice('Please enter a folder path.'); return; }
            this.close();
            const sep = folder.includes('\\') ? '\\' : '/';
            this.onChoose(folder.replace(/[\\/]+$/, '') + sep + 'vulnerabilities.csv');
        };

        const skipBtn = contentEl.createEl('button', { text: 'Skip (import without saving)' });
        skipBtn.style.cssText = 'width:100%;';
        skipBtn.onclick = () => { this.close(); this.onChoose(null); };

        input.addEventListener('keydown', e => { if (e.key === 'Enter') saveBtn.click(); });
        input.focus();
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

        containerEl.createEl('h3', { text: 'API credentials' });
        containerEl.createEl('p', {
            text: 'Credentials are stored in plain text in the plugin data file. Leave blank to be prompted each time.',
            cls: 'setting-item-description',
        });

        new Setting(containerEl)
            .setName('PwnDoc URL')
            .addText(t => t
                .setPlaceholder('https://localhost:8443')
                .setValue(this.plugin.settings.apiUrl)
                .onChange(async v => { this.plugin.settings.apiUrl = v.trim(); await this.plugin.saveSettings(); }));

        new Setting(containerEl)
            .setName('Username')
            .addText(t => t
                .setValue(this.plugin.settings.apiUsername)
                .onChange(async v => { this.plugin.settings.apiUsername = v.trim(); await this.plugin.saveSettings(); }));

        new Setting(containerEl)
            .setName('Password')
            .addText(t => {
                t.inputEl.type = 'password';
                t.setValue(this.plugin.settings.apiPassword)
                 .onChange(async v => { this.plugin.settings.apiPassword = v; await this.plugin.saveSettings(); });
            });

        new Setting(containerEl)
            .setName('Ignore SSL certificate errors')
            .setDesc('Enable for self-signed certificates')
            .addToggle(tg => tg
                .setValue(this.plugin.settings.apiIgnoreSsl)
                .onChange(async v => { this.plugin.settings.apiIgnoreSsl = v; await this.plugin.saveSettings(); }));

        containerEl.createEl('h3', { text: 'CSV output' });

        new Setting(containerEl)
            .setName('Default CSV output folder')
            .setDesc('Absolute path to the folder where vulnerabilities.csv will be saved after an API fetch. Leave blank to be prompted each time.')
            .addText(t => t
                .setPlaceholder('C:/tools/pwndoc')
                .setValue(this.plugin.settings.csvOutputFolder)
                .onChange(async v => { this.plugin.settings.csvOutputFolder = v.trim(); await this.plugin.saveSettings(); }));

        containerEl.createEl('h3', { text: 'Debug' });

        new Setting(containerEl)
            .setName('Debug mode')
            .setDesc('Log detailed information to the browser console (Ctrl+Shift+I → Console) during API imports.')
            .addToggle(tg => tg
                .setValue(this.plugin.settings.debugMode)
                .onChange(async v => { this.plugin.settings.debugMode = v; await this.plugin.saveSettings(); }));
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
        this.addCommand({
            id: 'import-vuln-from-api',
            name: 'Fetch and import vulnerability from PwnDoc API',
            callback: () => this.openApiImportModal(),
        });
    }

    async loadSettings() {
        this.settings = Object.assign({}, DEFAULT_SETTINGS, await this.loadData());
    }
    async saveSettings() { await this.saveData(this.settings); }

    dbg(...args) {
        if (this.settings.debugMode) console.log('[PwnDoc Importer]', ...args);
    }

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

    // API import — step 1: ask for credentials (pre-filled from settings)
    openApiImportModal() {
        new ApiCredentialsModal(this.app, this.settings, creds => this.fetchFromApi(creds)).open();
    }

    // API import — step 2: connect, optionally save CSV, then open vuln search
    async fetchFromApi({ url, username, password, ignoreSsl, save }) {
        if (save) {
            this.settings.apiUrl      = url;
            this.settings.apiUsername = username;
            this.settings.apiPassword = password;
            this.settings.apiIgnoreSsl = ignoreSsl;
            await this.saveSettings();
        }
        const dbg = this.dbg.bind(this);
        const notice = new Notice('PwnDoc Importer: connecting…', 0);
        let rows;
        try {
            dbg('logging in to', url);
            const token = await pwndocLogin(url, username, password, ignoreSsl);
            dbg('login OK, fetching vulns + custom fields');
            notice.setMessage('PwnDoc Importer: fetching vulnerabilities…');
            const [vulns, cfLabels] = await Promise.all([
                pwndocFetchVulns(url, token, ignoreSsl),
                pwndocFetchCustomFields(url, token, ignoreSsl, dbg).catch(e => { dbg('custom fields fetch failed:', e.message); return {}; }),
            ]);
            notice.hide();

            dbg(`fetched ${vulns.length} vulns, ${Object.keys(cfLabels).length} custom field definitions`);
            dbg('cfLabels map:', cfLabels);
            this.cfLabels = cfLabels;
            rows = flattenVulnsFromApi(vulns, cfLabels);
            dbg(`flattened to ${rows.length} rows; sample keys:`, rows[0] ? Object.keys(rows[0]) : []);
            if (rows.length === 0) { new Notice('PwnDoc Importer: no vulnerabilities returned from API.'); return; }
        } catch (e) {
            notice.hide();
            new Notice(`PwnDoc Importer: ${e.message}`);
            console.error(e);
            return;
        }

        // Step 3: ask where to save the CSV (or skip)
        new CsvOutputModal(this.app, this.settings.csvOutputFolder, async csvPath => {
            if (csvPath) {
                try {
                    require('fs').writeFileSync(csvPath, rowsToCsv(rows), 'utf8');
                    new Notice(`PwnDoc Importer: CSV saved to ${csvPath}`);
                } catch (e) {
                    new Notice(`PwnDoc Importer: could not save CSV — ${e.message}`);
                    console.error(e);
                    // Continue anyway — don't block the import
                }
            }

            // Step 4: apply locale filter and open search
            const { locale } = this.settings;
            let filtered = rows;
            if (locale) {
                const f = rows.filter(r => r.locale === locale);
                if (f.length > 0) filtered = f;
            }
            new VulnSearchModal(this.app, filtered, vuln => this.askPrefix(vuln)).open();
        }).open();
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

        // OWASP + CWE — resolve setting id (may be cf_<id> or label) to actual row key
        const cfLabels = this.cfLabels || {};
        const resolveKey = s => (s.startsWith('cf_') && cfLabels[s.slice(3)]) ? cfLabels[s.slice(3)] : s;
        const owaspKey = resolveKey(this.settings.owaspFieldId);
        const cweKey   = resolveKey(this.settings.cweFieldId);
        const owasp = vuln[owaspKey] || '';
        const cwe   = vuln[cweKey]   || '';

        // Extra custom fields (non-standard, non-owasp/cwe, non-empty)
        const reservedKeys = new Set([owaspKey, cweKey, this.settings.owaspFieldId, this.settings.cweFieldId]);
        const extraCf = Object.keys(vuln)
            .filter(k => !STANDARD_FIELDS.has(k) && !reservedKeys.has(k))
            .map(k => ({
                label: k,
                value: stripHtml(vuln[k] || '').trim(),
            }))
            .filter(({ value }) => value !== '');

        // Content sections (HTML stripped)
        const description  = stripHtml(vuln.description);
        const observation  = stripHtml(vuln.observation);
        const remediation  = stripHtml(vuln.remediation);
        const references   = vuln.references || '';

        const title    = (vuln.title || 'Untitled').replace(/[\\/:*?"<>|]/g, '-');
        const noteName = `${prefix}-${num} - ${title}`;
        const filePath = folder ? `${folder}/${noteName}.md` : `${noteName}.md`;

        // Custom fields section at the end
        const cfSection = extraCf.length > 0
            ? ['## Custom Fields', '', ...extraCf.flatMap(({ label, value }) => [`**${label}**`, '', value, ''])]
            : [];

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
            ...(references ? ['## References', '', references, ''] : []),
            ...cfSection,
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

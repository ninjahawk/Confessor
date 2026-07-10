/**
 * Renders the entire report as ONE self-contained HTML file: inline CSS,
 * inline vanilla JS, inline SVG. No CDN, no fonts, no fetches — it must render
 * identically with the network cable unplugged. A strict CSP meta tag is
 * included so even injected content could not load remote resources.
 *
 * Every dynamic string is HTML-escaped; every preview arriving here was
 * already redacted by the detection layer.
 *
 * Design language: quiet, light, and legible for someone who has never heard
 * the words "credential" or "PII" — plain sentences, one accent color, system
 * fonts, white cards on the classic soft-gray canvas.
 */
import type {
  ScanResult,
  Finding,
  Provider,
  TimelinePoint,
  TimelineGroup,
  CategoryId,
} from '../types.js';
import { PROVIDER_LABELS, CATEGORY_LABELS } from '../types.js';
import { escapeHtml as esc, comma, formatDate, formatMonth } from '../util.js';
import { gradeColor, SEVERITY_COLORS } from '../score.js';

const TIMELINE_COLORS: Record<TimelineGroup, string> = {
  secrets: '#ff3b30',
  pii: '#ff9500',
  health: '#34c759',
  'mental-health': '#af52de',
  legal: '#007aff',
  financial: '#ff2d55',
  employment: '#5ac8fa',
  relationships: '#ffcc00',
  identity: '#8e8e93',
};

const TIMELINE_LABELS: Record<TimelineGroup, string> = {
  secrets: 'Passwords & keys',
  pii: 'Personal details',
  health: 'Health',
  'mental-health': 'Mental health',
  legal: 'Legal',
  financial: 'Money',
  employment: 'Work',
  relationships: 'Relationships',
  identity: 'Identity',
};

const CATEGORY_BLURBS: Record<CategoryId, string> = {
  health: 'conditions, medications, treatments',
  'mental-health': 'therapy, diagnoses, difficult moments',
  legal: 'lawyers, cases, immigration, arrests',
  financial: 'salary, debt, account balances',
  employment: 'bosses, firings, workplace trouble',
  relationships: 'family, partners, breakups',
  identity: 'your name, employer, location, age',
};

const MAX_TABLE_ROWS = 500;
const MAX_CATEGORY_ROWS = 60;

/** One plain sentence a non-technical reader can act on, chosen by grade. */
function gradeSentence(result: ScanResult): string {
  const c = result.stats.counts;
  if (c.critical > 0) {
    return `We found ${comma(c.critical)} password${c.critical === 1 ? '' : 's'} or key${c.critical === 1 ? '' : 's'} in your AI conversations. They still work until you change them — this report shows you exactly where and how.`;
  }
  if (c.high > 0) {
    return `No passwords or keys — but ${comma(c.high)} personal detail${c.high === 1 ? ' has' : 's have'} ended up in your conversations, like email addresses or phone numbers.`;
  }
  if (c.medium > 0) {
    return `No passwords or personal identifiers were found. Some private topics have come up in conversation — worth a look, nothing urgent.`;
  }
  return `Your AI conversations look clean. Nothing sensitive was found.`;
}

function severityDot(sev: string): string {
  return `<span class="dot dot-${sev}"></span>`;
}

function whereCell(f: Finding): string {
  const first = f.occurrences[0];
  if (!first) return '<span class="dim">—</span>';
  const more = f.count > 1 ? ` <span class="dim">+${comma(f.count - 1)} more</span>` : '';
  return `<span class="prov">${esc(PROVIDER_LABELS[first.provider])}</span> <span class="convtitle">${esc(truncateTitle(first.conversationTitle))}</span>${more}`;
}

function truncateTitle(t: string): string {
  return t.length > 60 ? t.slice(0, 59) + '…' : t;
}

function renderProviderBars(result: ScanResult): string {
  const max = Math.max(...result.perProvider.map((p) => p.score), 1);
  return result.perProvider
    .map((p) => {
      const pct = Math.max((p.score / max) * 100, 1.5);
      return `
      <div class="provider-row">
        <div class="provider-name">${esc(p.label)}</div>
        <div class="provider-bar-track">
          <div class="provider-bar" style="width:${pct.toFixed(1)}%;background:${gradeColor(p.grade)}"></div>
        </div>
        <div class="provider-score"><span class="grade-chip" style="color:${gradeColor(p.grade)}">${p.grade}</span></div>
        <div class="provider-meta dim">${comma(p.conversations)} conversation${p.conversations === 1 ? '' : 's'} · ${comma(p.messages)} message${p.messages === 1 ? '' : 's'} · ${p.counts.critical} password${p.counts.critical === 1 ? '' : 's'}/keys · ${p.counts.high} personal detail${p.counts.high === 1 ? '' : 's'} · ${p.counts.medium} private topic${p.counts.medium === 1 ? '' : 's'}</div>
      </div>`;
    })
    .join('\n');
}

function renderFindingsTable(result: ScanResult): string {
  const rows = result.findings.filter((f) => f.severity !== 'medium');
  const shown = rows.slice(0, MAX_TABLE_ROWS);
  const providers = result.stats.providers;

  const provChips =
    providers.length > 1
      ? `<div class="chips" id="prov-chips">
          <button class="chip active" data-prov="all">Everywhere</button>
          ${providers.map((p) => `<button class="chip" data-prov="${esc(p)}">${esc(PROVIDER_LABELS[p])}</button>`).join('')}
        </div>`
      : '';

  const tableRows = shown
    .map((f) => {
      const fix = f.remediation ? `<span class="fix">${esc(f.remediation)}</span>` : '<span class="dim">—</span>';
      return `<tr data-sev="${f.severity}" data-prov="${f.providers.join(' ')}">
        <td class="titlecell">${severityDot(f.severity)} ${esc(f.title)}</td>
        <td><code class="preview">${esc(f.preview)}</code></td>
        <td>${whereCell(f)}</td>
        <td class="nowrap dim">${esc(formatDate(f.firstSeen?.timestamp))}</td>
        <td class="right dim">${comma(f.count)}</td>
        <td class="fixcell">${fix}</td>
      </tr>`;
    })
    .join('\n');

  const truncNote =
    rows.length > shown.length
      ? `<p class="dim small">Showing ${comma(shown.length)} of ${comma(rows.length)} — run <code>confessor --json</code> for the full list.</p>`
      : '';

  const empty = rows.length === 0 ? `<p class="allclear">Nothing here — no passwords, keys, or personal identifiers were found. That is genuinely rare.</p>` : '';

  return `
    <div class="chips" id="sev-chips">
      <button class="chip active" data-sev="all">Everything</button>
      <button class="chip" data-sev="critical"><span class="dot dot-critical"></span> Passwords &amp; keys (${comma(result.stats.counts.critical)})</button>
      <button class="chip" data-sev="high"><span class="dot dot-high"></span> Personal details (${comma(result.stats.counts.high)})</button>
    </div>
    ${provChips}
    ${empty}
    ${rows.length > 0 ? `<div class="card tablewrap"><table id="findings-table">
      <thead><tr><th>What it is</th><th>Preview (hidden for safety)</th><th>Where</th><th>First seen</th><th class="right">Times</th><th>How to fix it</th></tr></thead>
      <tbody>${tableRows}</tbody>
    </table></div>` : ''}
    ${truncNote}`;
}

function renderCategoryCards(result: ScanResult): string {
  const catFindings = result.findings.filter((f) => f.layer === 3);
  const byCat = new Map<CategoryId, Finding[]>();
  for (const f of catFindings) {
    if (!f.category) continue;
    const list = byCat.get(f.category) ?? [];
    list.push(f);
    byCat.set(f.category, list);
  }
  const order: CategoryId[] = ['health', 'mental-health', 'legal', 'financial', 'employment', 'relationships', 'identity'];
  const cards = order
    .map((cat) => {
      const list = byCat.get(cat) ?? [];
      const occurrences = list.reduce((a, f) => a + f.count, 0);
      const color = TIMELINE_COLORS[cat];
      if (list.length === 0) {
        return `<div class="card cat-card cat-empty">
          <div class="cat-head"><span class="cat-swatch" style="background:${color}"></span><strong>${esc(CATEGORY_LABELS[cat])}</strong></div>
          <div class="cat-count dim">nothing found</div>
          <div class="cat-blurb dim">${esc(CATEGORY_BLURBS[cat])}</div>
        </div>`;
      }
      const items = list
        .slice(0, MAX_CATEGORY_ROWS)
        .map((f) => {
          const first = f.occurrences[0];
          const where = first
            ? `<span class="prov">${esc(PROVIDER_LABELS[first.provider])}</span> ${esc(truncateTitle(first.conversationTitle))} <span class="dim">· ${esc(formatDate(f.firstSeen?.timestamp))} · ${comma(f.count)}×</span>`
            : '';
          const examples = (f.examples ?? [])
            .map((e) => `<li><code class="preview">${esc(e)}</code></li>`)
            .join('');
          return `<li class="cat-item">${where}${examples ? `<ul class="examples">${examples}</ul>` : ''}</li>`;
        })
        .join('\n');
      const moreNote =
        list.length > MAX_CATEGORY_ROWS ? `<div class="dim small">+ ${comma(list.length - MAX_CATEGORY_ROWS)} more conversations</div>` : '';
      return `<div class="card cat-card">
        <div class="cat-head"><span class="cat-swatch" style="background:${color}"></span><strong>${esc(CATEGORY_LABELS[cat])}</strong></div>
        <div class="cat-count"><span class="big">${comma(list.length)}</span> conversation${list.length === 1 ? '' : 's'} <span class="dim">· mentioned ${comma(occurrences)} time${occurrences === 1 ? '' : 's'}</span></div>
        <div class="cat-blurb dim">${esc(CATEGORY_BLURBS[cat])}</div>
        <details><summary>Show the conversations</summary><ul class="cat-list">${items}</ul>${moreNote}</details>
      </div>`;
    })
    .join('\n');
  return `<div class="cat-grid">${cards}</div>
  <p class="dim small">This section looks for topics, not exact matches, so expect the occasional miss — glance at the conversations before drawing conclusions.</p>`;
}

function renderTimeline(timeline: TimelinePoint[]): string {
  if (timeline.length === 0) {
    return '<p class="dim">These conversations have no dates attached, so there is no timeline to draw.</p>';
  }
  const W = 1000;
  const H = 230;
  const PAD_L = 46;
  const PAD_B = 34;
  const PAD_T = 12;
  const plotW = W - PAD_L - 8;
  const plotH = H - PAD_B - PAD_T;
  const maxTotal = Math.max(...timeline.map((t) => t.total), 1);
  const n = timeline.length;
  const slot = plotW / n;
  const barW = Math.max(Math.min(slot * 0.72, 44), 2);
  const groups = Object.keys(TIMELINE_COLORS) as TimelineGroup[];

  let bars = '';
  timeline.forEach((point, i) => {
    const x = PAD_L + i * slot + (slot - barW) / 2;
    let y = PAD_T + plotH;
    for (const g of groups) {
      const v = point.counts[g] ?? 0;
      if (v <= 0) continue;
      const h = (v / maxTotal) * plotH;
      y -= h;
      bars += `<rect x="${x.toFixed(1)}" y="${y.toFixed(1)}" width="${barW.toFixed(1)}" height="${Math.max(h, 0.5).toFixed(1)}" rx="1.5" fill="${TIMELINE_COLORS[g]}"><title>${formatMonth(point.month)} — ${TIMELINE_LABELS[g]}: ${v}</title></rect>`;
    }
  });

  const labelEvery = Math.max(1, Math.ceil(n / 12));
  let labels = '';
  timeline.forEach((point, i) => {
    if (i % labelEvery !== 0 && i !== n - 1) return;
    const x = PAD_L + i * slot + slot / 2;
    labels += `<text x="${x.toFixed(1)}" y="${H - 12}" text-anchor="middle" class="axis">${formatMonth(point.month)}</text>`;
  });

  const gridLines = [0, 0.5, 1]
    .map((f) => {
      const y = PAD_T + plotH - f * plotH;
      const val = Math.round(f * maxTotal);
      return `<line x1="${PAD_L}" y1="${y.toFixed(1)}" x2="${W - 8}" y2="${y.toFixed(1)}" class="grid"/><text x="${PAD_L - 8}" y="${(y + 4).toFixed(1)}" text-anchor="end" class="axis">${comma(val)}</text>`;
    })
    .join('');

  const legend = groups
    .map((g) => `<span class="legend-item"><span class="cat-swatch" style="background:${TIMELINE_COLORS[g]}"></span>${TIMELINE_LABELS[g]}</span>`)
    .join('');

  return `<div class="card chart-card"><svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Sensitive mentions per month" class="timeline-svg">${gridLines}${bars}${labels}</svg>
  <div class="legend">${legend}</div></div>`;
}

function renderWorst(result: ScanResult): string {
  if (result.worstConversations.length === 0) return '<p class="dim">Nothing to clean up — your history came back clean.</p>';
  const max = result.worstConversations[0].score || 1;
  return `<div class="card"><ol class="worst">${result.worstConversations
    .map((c) => {
      const pct = Math.max((c.score / max) * 100, 2);
      const range =
        c.firstTimestamp && c.lastTimestamp && formatDate(c.firstTimestamp) !== formatDate(c.lastTimestamp)
          ? `${formatDate(c.firstTimestamp)} – ${formatDate(c.lastTimestamp)}`
          : formatDate(c.firstTimestamp ?? c.lastTimestamp);
      return `<li>
        <div class="worst-title"><span class="prov">${esc(PROVIDER_LABELS[c.provider])}</span> ${esc(truncateTitle(c.title))}</div>
        <div class="worst-bar-track"><div class="worst-bar" style="width:${pct.toFixed(1)}%"></div></div>
        <div class="worst-meta dim">${esc(range)} · ${c.counts.critical} password${c.counts.critical === 1 ? '' : 's'}/keys · ${c.counts.high} personal detail${c.counts.high === 1 ? '' : 's'} · ${c.counts.medium} private topic${c.counts.medium === 1 ? '' : 's'}</div>
      </li>`;
    })
    .join('\n')}</ol></div>`;
}

const PROVIDER_ACTIONS: Record<Provider, { title: string; steps: string[] }> = {
  chatgpt: {
    title: 'ChatGPT',
    steps: [
      'Delete sensitive conversations: go to chatgpt.com, click your profile picture → Settings → Data controls → Delete all chats. (Or delete single chats from the list on the left.)',
      'Stop your chats being used for training: Settings → Data controls → turn off “Improve the model for everyone”.',
      'Ask OpenAI to delete your data: <a href="https://privacy.openai.com" rel="noopener">privacy.openai.com</a>.',
    ],
  },
  claude: {
    title: 'Claude',
    steps: [
      'Delete sensitive conversations: on claude.ai, hover over a chat in the sidebar and choose Delete. (Settings → Privacy can delete everything at once.)',
      'Check your training preference: Settings → Privacy → “Help improve Claude”.',
      'Ask Anthropic to delete your data: <a href="https://privacy.anthropic.com" rel="noopener">privacy.anthropic.com</a>.',
    ],
  },
  'claude-code': {
    title: 'Claude Code (files on this computer)',
    steps: [
      'These are files saved on your own computer, in the <code>.claude/projects</code> folder in your home folder. Deleting a session file removes that history.',
      'More important: any password or key that appears in them may also have been sent to the AI while you worked. Change those first — the table above says how.',
    ],
  },
  gemini: {
    title: 'Gemini',
    steps: [
      'Delete your activity: <a href="https://myactivity.google.com/product/gemini" rel="noopener">myactivity.google.com/product/gemini</a>.',
      'Set it to auto-delete: on the same page, “Choose an auto-delete option” (every 3, 18, or 36 months).',
      'Turn off Gemini Apps Activity if you don’t want conversations saved at all.',
    ],
  },
  generic: {
    title: 'Files you scanned',
    steps: ['These came from files you pointed the scanner at — edit or delete them wherever they live.'],
  },
};

function renderActions(result: ScanResult): string {
  const critical = result.stats.counts.critical;
  const urgent =
    critical > 0
      ? `<div class="urgent"><strong>Change ${critical === 1 ? 'this password or key' : `these ${comma(critical)} passwords and keys`} first.</strong> Deleting a chat doesn’t take back a password that was already shared — it keeps working until you change it. Every row in the table above says where to do that.</div>`
      : '';
  const cards = result.stats.providers
    .map((p) => {
      const a = PROVIDER_ACTIONS[p];
      return `<div class="card action-card"><h3>${esc(a.title)}</h3><ol>${a.steps.map((s) => `<li>${s}</li>`).join('')}</ol></div>`;
    })
    .join('\n');
  return `${urgent}<div class="action-grid">${cards}</div>
  <p class="dim small">A good habit from here on: never paste real passwords or keys into a chat — use a placeholder like <code>MY_PASSWORD</code> instead.</p>`;
}

function shareStatsJson(result: ScanResult): string {
  // Counts only — the share card must be safe by construction.
  const data = {
    conversations: result.stats.conversations,
    messages: result.stats.messages,
    providers: result.stats.providers.map((p) => PROVIDER_LABELS[p]),
    critical: result.stats.counts.critical,
    high: result.stats.counts.high,
    medium: result.stats.counts.medium,
    score: result.stats.score,
    grade: result.stats.grade,
    gradeColor: gradeColor(result.stats.grade),
    date: formatDate(Date.parse(result.generatedAt)),
  };
  return JSON.stringify(data).replace(/</g, '\\u003c');
}

const INLINE_JS = `
(function () {
  'use strict';
  var sevFilter = 'all';
  var provFilter = 'all';
  function applyFilters() {
    var rows = document.querySelectorAll('#findings-table tbody tr');
    for (var i = 0; i < rows.length; i++) {
      var r = rows[i];
      var okSev = sevFilter === 'all' || r.getAttribute('data-sev') === sevFilter;
      var okProv = provFilter === 'all' || (r.getAttribute('data-prov') || '').split(' ').indexOf(provFilter) !== -1;
      r.style.display = okSev && okProv ? '' : 'none';
    }
  }
  function wireChips(containerId, attr, cb) {
    var box = document.getElementById(containerId);
    if (!box) return;
    box.addEventListener('click', function (e) {
      var btn = e.target.closest('button.chip');
      if (!btn) return;
      var chips = box.querySelectorAll('.chip');
      for (var i = 0; i < chips.length; i++) chips[i].classList.remove('active');
      btn.classList.add('active');
      cb(btn.getAttribute(attr) || 'all');
    });
  }
  wireChips('sev-chips', 'data-sev', function (v) { sevFilter = v; applyFilters(); });
  wireChips('prov-chips', 'data-prov', function (v) { provFilter = v; applyFilters(); });

  var expandBtn = document.getElementById('expand-all');
  if (expandBtn) {
    expandBtn.addEventListener('click', function () {
      var open = expandBtn.getAttribute('data-open') !== '1';
      var det = document.querySelectorAll('details');
      for (var i = 0; i < det.length; i++) det[i].open = open;
      expandBtn.setAttribute('data-open', open ? '1' : '0');
      expandBtn.textContent = open ? 'Collapse all' : 'Expand all';
    });
  }

  // ---- share card (counts only; zero content by construction) ----
  var stats = window.__CONFESSOR_STATS__;
  var canvas = document.getElementById('share-canvas');
  if (!canvas || !stats) return;
  var ctx = canvas.getContext('2d');
  var W = 1200, H = 630;
  var SYS = '-apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif';

  function rr(x, y, w, h, r) {
    ctx.beginPath();
    ctx.moveTo(x + r, y);
    ctx.arcTo(x + w, y, x + w, y + h, r);
    ctx.arcTo(x + w, y + h, x, y + h, r);
    ctx.arcTo(x, y + h, x, y, r);
    ctx.arcTo(x, y, x + w, y, r);
    ctx.closePath();
  }

  function draw() {
    ctx.fillStyle = '#f5f5f7';
    ctx.fillRect(0, 0, W, H);
    ctx.fillStyle = '#ffffff';
    rr(40, 40, W - 80, H - 80, 36);
    ctx.fill();

    ctx.fillStyle = '#1d1d1f';
    ctx.font = '600 46px ' + SYS;
    ctx.fillText('My AI privacy check', 104, 156);
    ctx.fillStyle = '#86868b';
    ctx.font = '400 26px ' + SYS;
    ctx.fillText(stats.date + ' \\u00b7 ' + stats.providers.join(', '), 104, 200);

    var rows = [
      ['#ff3b30', stats.critical, 'passwords & keys'],
      ['#ff9500', stats.high, 'personal details'],
      ['#007aff', stats.medium, 'private topics']
    ];
    var y = 296;
    for (var i = 0; i < rows.length; i++) {
      ctx.fillStyle = rows[i][0];
      rr(104, y - 24, 24, 24, 7);
      ctx.fill();
      ctx.fillStyle = '#1d1d1f';
      ctx.font = '600 40px ' + SYS;
      ctx.fillText(fmt(rows[i][1]), 152, y);
      ctx.fillStyle = '#86868b';
      ctx.font = '400 27px ' + SYS;
      ctx.fillText(rows[i][2], 268, y - 3);
      y += 84;
    }

    ctx.strokeStyle = stats.gradeColor;
    ctx.lineWidth = 10;
    ctx.beginPath();
    ctx.arc(972, 315, 128, 0, Math.PI * 2);
    ctx.stroke();
    ctx.fillStyle = stats.gradeColor;
    ctx.font = '700 150px ' + SYS;
    ctx.textAlign = 'center';
    ctx.fillText(stats.grade, 972, 368);
    ctx.fillStyle = '#86868b';
    ctx.font = '400 25px ' + SYS;
    ctx.fillText('privacy grade', 972, 496);
    ctx.textAlign = 'left';

    ctx.fillStyle = '#34c759';
    ctx.beginPath();
    ctx.arc(112, 543, 7, 0, Math.PI * 2);
    ctx.fill();
    ctx.fillStyle = '#86868b';
    ctx.font = '400 24px ' + SYS;
    ctx.fillText('Checked privately on my own computer \\u00b7 npx confessor', 132, 552);
  }
  function fmt(n) { return String(n).replace(/\\B(?=(\\d{3})+(?!\\d))/g, ','); }
  draw();

  var dl = document.getElementById('share-download');
  if (dl) {
    dl.addEventListener('click', function () {
      var a = document.createElement('a');
      a.download = 'confessor-card.png';
      a.href = canvas.toDataURL('image/png');
      a.click();
    });
  }
})();
`;

const CSS = `
:root{color-scheme:light}
*{box-sizing:border-box}
body{margin:0;background:#f5f5f7;color:#1d1d1f;font:17px/1.5 -apple-system,BlinkMacSystemFont,"SF Pro Text","Segoe UI",Roboto,Helvetica,Arial,sans-serif;-webkit-font-smoothing:antialiased}
code,.preview{font-family:"SF Mono",ui-monospace,"Cascadia Code",Menlo,Consolas,monospace}
a{color:#0066cc;text-decoration:none}a:hover{text-decoration:underline}
.wrap{max-width:980px;margin:0 auto;padding:0 22px 100px}
header{position:sticky;top:0;z-index:5;background:rgba(255,255,255,.8);backdrop-filter:saturate(1.8) blur(20px);border-bottom:1px solid rgba(0,0,0,.08)}
.header-inner{max-width:980px;margin:0 auto;padding:13px 22px;display:flex;align-items:center;gap:14px}
.brand{font-weight:600;font-size:17px;letter-spacing:-.01em}
.header-inner .spacer{flex:1}
.chip-local{color:#248a3d;background:rgba(52,199,89,.12);padding:5px 13px;border-radius:99px;font-size:13px;font-weight:500;white-space:nowrap}
.gen-date{color:#86868b;font-size:14px}
.dim{color:#86868b}.small{font-size:14px}.right{text-align:right}.nowrap{white-space:nowrap}
h2{margin:88px 0 8px;font-size:32px;font-weight:600;letter-spacing:-.015em}
.sub{color:#86868b;margin:0 0 24px;font-size:17px;max-width:640px}
.card{background:#fff;border-radius:18px;box-shadow:0 1px 3px rgba(0,0,0,.04),0 8px 24px rgba(0,0,0,.04)}
.hero{padding:84px 0 0;text-align:center}
.hero h1{font-size:44px;line-height:1.15;font-weight:600;letter-spacing:-.02em;margin:0 auto 14px;max-width:760px}
.hero .lede{font-size:19px;color:#6e6e73;max-width:620px;margin:0 auto}
.grade-ring{width:132px;height:132px;border-radius:50%;margin:44px auto 10px;display:flex;align-items:center;justify-content:center;font-size:64px;font-weight:700;border:8px solid}
.grade-caption{color:#86868b;font-size:15px;margin-bottom:44px}
.stat-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;text-align:left}
.stat{padding:24px 26px}
.stat .value{font-size:44px;font-weight:600;letter-spacing:-.02em;line-height:1.1}
.stat .label{font-size:17px;font-weight:600;margin-top:2px}
.stat .expl{font-size:14px;color:#86868b;margin-top:6px;line-height:1.45}
.headline{margin:34px auto 0;font-size:17px;color:#6e6e73;max-width:640px}
.scanned-line{margin-top:8px;color:#86868b;font-size:15px}
.hero-note{color:#86868b;font-size:14px;max-width:560px;margin:26px auto 0}
.provider-row{display:grid;grid-template-columns:150px 1fr 56px;gap:12px;align-items:center;margin:14px 0}
.provider-name{font-weight:600;font-size:16px}
.provider-bar-track{background:#e8e8ed;border-radius:99px;height:14px;overflow:hidden}
.provider-bar{height:100%;border-radius:99px;min-width:6px}
.provider-score{text-align:right}
.grade-chip{font-weight:700;font-size:20px}
.provider-meta{grid-column:2/4;margin-top:-8px;font-size:13.5px}
.chips{display:flex;flex-wrap:wrap;gap:8px;margin:18px 0}
.chip{background:#e8e8ed;color:#1d1d1f;border:none;border-radius:99px;padding:8px 18px;font-size:15px;font-family:inherit;cursor:pointer;transition:background .15s}
.chip:hover{background:#dcdce1}
.chip.active{background:#1d1d1f;color:#fff}
.dot{display:inline-block;width:9px;height:9px;border-radius:99px;margin-right:3px}
.dot-critical{background:#ff3b30}.dot-high{background:#ff9500}.dot-medium{background:#007aff}
.chip.active .dot{outline:2px solid rgba(255,255,255,.6);outline-offset:1px}
.tablewrap{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:14.5px}
th{text-align:left;color:#86868b;font-weight:500;font-size:13px;padding:16px 18px 10px;border-bottom:1px solid #e8e8ed}
td{padding:13px 14px;border-bottom:1px solid #f0f0f2;vertical-align:top}
th:first-child,td:first-child{padding-left:20px}
th:last-child,td:last-child{padding-right:20px}
th:nth-child(2),td:nth-child(2){min-width:210px}
th:nth-child(3),td:nth-child(3){min-width:120px}
.titlecell{min-width:130px;font-weight:500}
tr:last-child td{border-bottom:none}
.preview{background:#f5f5f7;border-radius:6px;padding:3px 8px;font-size:12.5px;word-break:break-all;color:#515154}
.fix,.fixcell{font-size:13px;color:#6e6e73;max-width:190px;min-width:150px}
.prov{font-size:12px;font-weight:600;padding:3px 9px;border-radius:99px;background:#e8e8ed;color:#515154;white-space:nowrap}
.convtitle{color:#1d1d1f}
.allclear{background:rgba(52,199,89,.12);color:#248a3d;padding:16px 20px;border-radius:14px;font-weight:500}
.cat-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(290px,1fr));gap:16px}
.cat-card{padding:22px 24px}
.cat-card.cat-empty{opacity:.55;box-shadow:none;background:rgba(255,255,255,.6)}
.cat-head{display:flex;align-items:center;gap:9px;font-size:17px}
.cat-swatch{display:inline-block;width:11px;height:11px;border-radius:4px;flex:none}
.cat-count{margin:10px 0 2px;font-size:15px}.cat-count .big{font-size:28px;font-weight:600;letter-spacing:-.01em}
.cat-blurb{font-size:13.5px}
details{margin-top:12px}
summary{cursor:pointer;color:#0066cc;font-size:14px;font-weight:500}
.cat-list{list-style:none;margin:12px 0 0;padding:0;max-height:340px;overflow-y:auto}
.cat-item{padding:10px 0;border-top:1px solid #f0f0f2;font-size:14px}
.examples{margin:6px 0 0;padding-left:14px;list-style:none}
.examples li{margin:4px 0}
.chart-card{padding:22px 24px}
.timeline-svg{width:100%;height:auto}
.timeline-svg .grid{stroke:#e8e8ed;stroke-width:1}
.timeline-svg .axis{fill:#86868b;font-size:11px;font-family:-apple-system,"Segoe UI",sans-serif}
.legend{display:flex;flex-wrap:wrap;gap:8px 18px;margin-top:14px;font-size:13.5px;color:#6e6e73}
.legend-item{display:inline-flex;align-items:center;gap:6px}
.worst{margin:0;padding:10px 20px 10px 40px}
.worst li{margin:18px 0;padding-right:16px}
.worst-title{font-size:15.5px;margin-bottom:6px}
.worst-bar-track{background:#e8e8ed;border-radius:99px;height:8px;overflow:hidden}
.worst-bar{height:100%;border-radius:99px;background:linear-gradient(90deg,#ff3b30,#ff9500)}
.worst-meta{font-size:13px;margin-top:5px}
.urgent{background:rgba(255,59,48,.08);color:#c0392b;border-radius:14px;padding:18px 22px;margin-bottom:18px;font-size:16px;line-height:1.5}
.urgent strong{color:#a52a21}
.action-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:16px}
.action-card{padding:22px 24px}
.action-card h3{margin:0 0 12px;font-size:18px;font-weight:600;letter-spacing:-.01em}
.action-card ol{margin:0;padding-left:20px;font-size:14.5px;color:#424245}
.action-card li{margin:9px 0;line-height:1.5}
.share-box{padding:26px;display:flex;flex-direction:column;gap:18px;align-items:flex-start}
#share-canvas{width:100%;max-width:640px;height:auto;border-radius:14px}
.btn{background:#0071e3;border:none;color:#fff;border-radius:99px;padding:11px 24px;font-size:15px;font-weight:500;font-family:inherit;cursor:pointer}
.btn:hover{background:#0077ed}
.toolbar{display:flex;justify-content:flex-end;margin:6px 0}
.linklike{background:none;border:none;color:#0066cc;cursor:pointer;font-size:14px;font-weight:500;font-family:inherit;padding:0}
footer{margin-top:110px;border-top:1px solid rgba(0,0,0,.08);padding-top:22px;color:#86868b;font-size:13.5px;display:flex;flex-wrap:wrap;gap:6px 20px}
@media(max-width:760px){.stat-grid{grid-template-columns:1fr}.provider-row{grid-template-columns:110px 1fr 44px}.hero h1{font-size:32px}h2{font-size:26px}}
`;

export function renderReport(result: ScanResult): string {
  const { stats } = result;
  const providersLine = result.perProvider.map((p) => p.label).join(', ');
  const gc = gradeColor(stats.grade);

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:;">
<meta name="color-scheme" content="light">
<title>Your AI privacy report</title>
<style>${CSS}</style>
</head>
<body>
<header><div class="header-inner">
  <span class="brand">Confessor</span>
  <span class="gen-date">${esc(formatDate(Date.parse(result.generatedAt)))}</span>
  <span class="spacer"></span>
  <span class="chip-local">Private — nothing leaves this computer</span>
</div></header>
<div class="wrap">

<section class="hero" id="top">
  <h1>Your AI privacy report</h1>
  <p class="lede">${esc(gradeSentence(result))}</p>
  <div class="grade-ring" style="color:${gc};border-color:${gc}">${esc(stats.grade)}</div>
  <div class="grade-caption">Your privacy grade · ${comma(stats.score)} points — lower is better</div>
  <div class="stat-grid">
    <div class="card stat"><div class="value" style="color:${stats.counts.critical > 0 ? SEVERITY_COLORS.critical : '#34c759'}">${comma(stats.counts.critical)}</div><div class="label">Passwords &amp; keys</div><div class="expl">Things that can unlock your accounts. If this number isn’t zero, fix these first.</div></div>
    <div class="card stat"><div class="value" style="color:${stats.counts.high > 0 ? SEVERITY_COLORS.high : '#34c759'}">${comma(stats.counts.high)}</div><div class="label">Personal details</div><div class="expl">Your email, phone number, address, card number — details that identify you.</div></div>
    <div class="card stat"><div class="value" style="color:${stats.counts.medium > 0 ? SEVERITY_COLORS.medium : '#34c759'}">${comma(stats.counts.medium)}</div><div class="label">Private topics</div><div class="expl">Health, money, work, and other personal subjects you’ve discussed.</div></div>
  </div>
  ${result.headline ? `<p class="headline">${esc(result.headline)}</p>` : ''}
  <p class="scanned-line">Based on ${comma(stats.messages)} messages in ${comma(stats.conversations)} conversations from ${esc(providersLine)}.</p>
  <div class="hero-note">This report was created entirely on your computer and only exists as this file. The previews inside are partly hidden for safety — but the file still maps out where your private information is, so treat it as private too.</div>
</section>

<section id="sources">
  <h2>Where it came from</h2>
  <p class="sub">Each service is graded on how much sensitive information ended up there. If one bar stands out, that’s where to focus.</p>
  <div class="card" style="padding:26px 28px">${renderProviderBars(result)}</div>
</section>

<section id="findings">
  <h2>What we found</h2>
  <p class="sub">Every password, key, and personal detail, with a partly-hidden preview — the full values are never written into this report — and plain instructions for fixing each one.</p>
  ${renderFindingsTable(result)}
</section>

<section id="disclosures">
  <h2>What you've shared about yourself</h2>
  <p class="sub">Personal subjects that came up in your conversations, grouped by area of life. Nothing here needs fixing — it’s simply what these services now know about you.</p>
  <div class="toolbar"><button class="linklike" id="expand-all">Expand all</button></div>
  ${renderCategoryCards(result)}
</section>

<section id="timeline">
  <h2>Month by month</h2>
  <p class="sub">How often sensitive things came up over time.</p>
  ${renderTimeline(result.timeline)}
</section>

<section id="conversations">
  <h2>Chats to clean up first</h2>
  <p class="sub">If you only tidy up a few conversations, start with these.</p>
  ${renderWorst(result)}
</section>

<section id="actions">
  <h2>What to do now</h2>
  <p class="sub">Three kinds of cleanup: change any passwords that leaked, delete the chats you’d rather not keep, and switch off training on your conversations.</p>
  ${renderActions(result)}
</section>

<section id="share">
  <h2>Share your grade</h2>
  <p class="sub">A picture with your grade and the counts — nothing personal is on it, so it’s safe to post. Make your friends run their own check.</p>
  <div class="card share-box">
    <canvas id="share-canvas" width="1200" height="630"></canvas>
    <button class="btn" id="share-download">Download the picture</button>
  </div>
</section>

<footer>
  <span>Created by <strong>confessor</strong> v${esc(result.version)}</span>
  <span>Runs entirely on your computer — nothing is uploaded</span>
  <span>Free &amp; open source · github.com/ninjahawk/Confessor</span>
</footer>
</div>
<script>window.__CONFESSOR_STATS__ = ${shareStatsJson(result)};<\/script>
<script>${INLINE_JS}<\/script>
</body>
</html>`;
}

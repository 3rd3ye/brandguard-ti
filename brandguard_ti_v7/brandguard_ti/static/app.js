const form = document.getElementById('analyzeForm');
const summaryEl = document.getElementById('summary');
const reasonsEl = document.getElementById('reasons');
const insightsEl = document.getElementById('insights');
const intelFactsEl = document.getElementById('intelFacts');
const infraFactsEl = document.getElementById('infraFacts');
const signalFactsEl = document.getElementById('signalFacts');
const evidenceFactsEl = document.getElementById('evidenceFacts');
const accessFactsEl = document.getElementById('accessFacts');
const timelineFactsEl = document.getElementById('timelineFacts');
const extEl = document.getElementById('extensibility');
const screenshotEl = document.getElementById('screenshot');
const placeholderEl = document.getElementById('shotPlaceholder');
const riskScoreEl = document.getElementById('riskScore');
const verdictEl = document.getElementById('verdict');
const trademarkEl = document.getElementById('trademark');
const hostingEl = document.getElementById('hosting');
const scoreRing = document.getElementById('scoreRing');
const scoreBars = document.getElementById('scoreBars');
const statusText = document.getElementById('statusText');
const statusNote = document.getElementById('statusNote');
const progressText = document.getElementById('progressText');
const progressFill = document.getElementById('progressFill');

const BAR_LABELS = {
  phishing: 'Phishing',
  brand: 'Brand abuse',
  threat_intel: 'Threat intel',
  infrastructure: 'Infrastructure',
};

let activeJob = null;
let pollTimer = null;
let lastResult = null;

function setBusy(busy) {
  document.body.classList.toggle('busy', busy);
}

function setText(el, value) {
  el.textContent = value ?? '—';
}

function setRing(score) {
  const numeric = Number(score) || 0;
  const circumference = 289;
  const offset = circumference - Math.min(100, Math.max(0, numeric)) / 100 * circumference;
  scoreRing.style.strokeDashoffset = `${offset}`;
}

function makeTag(text, tone = 'tag') {
  const span = document.createElement('span');
  span.className = `tag ${tone}`;
  span.textContent = text;
  return span;
}

function renderTags(items) {
  reasonsEl.innerHTML = '';
  if (!items || !items.length) {
    reasonsEl.appendChild(makeTag('No reasons returned'));
    return;
  }
  for (const item of items) reasonsEl.appendChild(makeTag(item));
}

function renderBars(scores) {
  scoreBars.innerHTML = '';
  const entries = Object.entries(scores || {});
  for (const [key, value] of entries) {
    const row = document.createElement('div');
    row.className = 'bar-row';

    const head = document.createElement('div');
    head.className = 'bar-head';
    const label = document.createElement('span');
    label.textContent = BAR_LABELS[key] || key;
    const score = document.createElement('strong');
    score.textContent = `${value ?? 0}/100`;
    head.append(label, score);

    const track = document.createElement('div');
    track.className = 'bar-track';
    const fill = document.createElement('div');
    fill.className = 'bar-fill';
    fill.style.width = `${Math.max(0, Math.min(100, value || 0))}%`;
    track.appendChild(fill);

    row.append(head, track);
    scoreBars.appendChild(row);
  }
}

function toneClass(tone) {
  if (tone === 'critical') return 'critical';
  if (tone === 'high') return 'high';
  if (tone === 'medium') return 'medium';
  return 'low';
}

function renderInsightCards(cards) {
  insightsEl.innerHTML = '';
  if (!cards || !cards.length) {
    insightsEl.innerHTML = '<div class="insight-card"><div class="insight-head"><span class="badge low">low</span><strong>No narrative</strong></div><p>No narrative was generated.</p></div>';
    return;
  }

  for (const card of cards) {
    const wrap = document.createElement('article');
    wrap.className = 'insight-card';

    const head = document.createElement('div');
    head.className = 'insight-head';
    const badge = document.createElement('span');
    badge.className = `badge ${toneClass(card.tone)}`;
    badge.textContent = card.tone || 'low';
    const title = document.createElement('strong');
    title.textContent = card.title || 'Insight';
    head.append(badge, title);

    const list = document.createElement('ul');
    for (const bullet of card.bullets || []) {
      const li = document.createElement('li');
      li.textContent = bullet;
      list.appendChild(li);
    }

    wrap.append(head, list);
    insightsEl.appendChild(wrap);
  }
}

function renderFactList(container, items, emptyText) {
  container.innerHTML = '';
  if (!items || !items.length) {
    const row = document.createElement('div');
    row.className = 'fact-row';
    const strong = document.createElement('strong');
    strong.textContent = emptyText || 'No data available.';
    row.appendChild(strong);
    container.appendChild(row);
    return;
  }

  for (const item of items) {
    const row = document.createElement('div');
    row.className = 'fact-row';
    const label = document.createElement('span');
    label.textContent = item.label;
    const value = document.createElement('strong');
    value.textContent = item.value;
    row.append(label, value);
    container.appendChild(row);
  }
}

function prettyPath(path) {
  if (!path) return '—';
  return String(path).replace(/^\//, '');
}

function setStatus(pct, message, busy = true) {
  progressText.textContent = `${Math.max(0, Math.min(100, pct || 0))}%`;
  progressFill.style.width = `${Math.max(0, Math.min(100, pct || 0))}%`;
  statusText.textContent = message || 'Working';
  statusNote.textContent = message || 'Working';
  setBusy(busy);
}

function setIdleState() {
  setStatus(0, 'Idle', false);
  progressFill.style.width = '0%';
  progressText.textContent = '0%';
  statusNote.textContent = 'Paste a URL and run the analysis.';
}

function setScreenshotSource(source) {
  if (!source) {
    screenshotEl.removeAttribute('src');
    screenshotEl.style.display = 'none';
    placeholderEl.style.display = 'grid';
    return;
  }
  placeholderEl.style.display = 'grid';
  screenshotEl.style.display = 'none';
  screenshotEl.onload = () => {
    placeholderEl.style.display = 'none';
    screenshotEl.style.display = 'block';
  };
  screenshotEl.onerror = () => {
    screenshotEl.removeAttribute('src');
    screenshotEl.style.display = 'none';
    placeholderEl.style.display = 'grid';
  };
  const fresh = source.startsWith('data:') ? source : `${source}${source.includes('?') ? '&' : '?'}v=${Date.now()}`;
  screenshotEl.src = fresh;
}

function renderResult(data) {
  lastResult = data;
  setText(riskScoreEl, data.risk_score ?? '—');
  setText(verdictEl, data.verdict || '—');
  setText(trademarkEl, data.target?.brand_name ? (data.signals?.domain_mismatch || data.signals?.logo_match ? 'Concern raised' : 'No strong match') : 'Brand not supplied');
  setText(hostingEl, data.infrastructure?.provider_hint || data.infrastructure?.asn || '—');
  setRing(data.risk_score || 0);

  summaryEl.textContent = data.summary || (data.access?.analysis_limited ? 'The page was access-restricted and deeper inspection was limited.' : 'No summary returned.');
  renderTags(data.reasons || []);
  renderBars(data.category_scores || {});
  renderInsightCards(data.insight_cards || []);

  const access = data.access || {};
  const intel = data.threat_intel || {};
  const infra = data.infrastructure || {};
  const signals = data.signals || {};
  const evidence = data.evidence || {};

  renderFactList(intelFactsEl, [
    { label: 'Public feed', value: intel.urlhaus_hit ? 'URLhaus match' : 'No URLhaus match' },
    { label: 'Certificate transparency', value: intel.crtsh_hits ? `${intel.crtsh_hits} related result(s)` : 'No obvious CT hit' },
    { label: 'Intel level', value: intel.intel_level || 'unknown' },
    { label: 'Intel notes', value: (intel.notes || []).join(' ') || 'No strong public signal' },
  ], 'No threat intelligence details returned.');

  renderFactList(infraFactsEl, [
    { label: 'Host', value: infra.host || '—' },
    { label: 'IP address', value: infra.ip || '—' },
    { label: 'ASN', value: infra.asn || '—' },
    { label: 'Country', value: infra.country || '—' },
    { label: 'Provider hint', value: infra.provider_hint || '—' },
  ], 'No infrastructure data returned.');

  renderFactList(accessFactsEl, [
    { label: 'Access state', value: access.analysis_limited ? 'Restricted' : 'Full page captured' },
    { label: 'Captured page state', value: access.analysis_limited ? 'Limited by access controls' : 'Full page captured' },
    { label: 'Analysis mode', value: access.analysis_limited ? 'Passive only' : 'Full evidence pass' },
  ], 'No access details returned.');

  renderFactList(signalFactsEl, [
    { label: 'Password field', value: signals.has_password_field ? 'Detected' : 'Not detected' },
    { label: 'Off-domain form action', value: signals.off_domain_form_action ? 'Detected' : 'Not detected' },
    { label: 'Brand in host', value: signals.brand_in_host ? 'Yes' : 'No' },
    { label: 'Brand in text', value: signals.brand_in_text ? 'Yes' : 'No' },
    { label: 'Brand in title', value: signals.brand_in_title ? 'Yes' : 'No' },
    { label: 'Domain similarity', value: `${Math.round((signals.domain_similarity || 0) * 100)}%` },
    { label: 'Keyword hits', value: (signals.keywords_hit || []).length ? (signals.keywords_hit || []).join(', ') : 'None' },
  ], 'No signal summary returned.');

  const evidenceFacts = [];
  if (evidence.title) evidenceFacts.push({ label: 'Page title', value: evidence.title });
  if (evidence.form_count !== undefined) evidenceFacts.push({ label: 'Forms discovered', value: String(evidence.form_count) });
  if (evidence.links_count !== undefined) evidenceFacts.push({ label: 'Links discovered', value: String(evidence.links_count) });
  if (evidence.scripts_count !== undefined) evidenceFacts.push({ label: 'Scripts discovered', value: String(evidence.scripts_count) });
  if (evidence.redirects?.length) evidenceFacts.push({ label: 'Redirect hops', value: evidence.redirects.join(' → ') });
  if (evidence.screenshot) evidenceFacts.push({ label: 'Screenshot file', value: prettyPath(evidence.screenshot) });
  renderFactList(evidenceFactsEl, evidenceFacts, 'No evidence summary returned.');

  const timelineFacts = [];
  if (infra.domain_created) timelineFacts.push({ label: 'Created', value: String(infra.domain_created).replace('T', ' ').replace('Z', ' UTC') });
  if (infra.domain_last_changed) timelineFacts.push({ label: 'Last changed', value: String(infra.domain_last_changed).replace('T', ' ').replace('Z', ' UTC') });
  if (infra.domain_age_days !== undefined && infra.domain_age_days !== null) timelineFacts.push({ label: 'Domain age', value: `${infra.domain_age_days} day(s)` });
  if (infra.ownership_churn_indicator) timelineFacts.push({ label: 'Ownership churn', value: infra.ownership_churn_indicator });
  if (infra.privacy_proxy !== undefined) timelineFacts.push({ label: 'Registrant visibility', value: infra.privacy_proxy ? 'Redacted / hidden' : 'Visible' });
  if (infra.registrar) timelineFacts.push({ label: 'Registrar', value: infra.registrar });
  if (infra.name_servers?.length) timelineFacts.push({ label: 'Nameservers', value: infra.name_servers.join(', ') });
  renderFactList(timelineFactsEl, timelineFacts, 'No timeline data returned.');

  extEl.textContent = data.extensibility?.architecture || 'Modular detectors and enrichment remain available for future expansion.';

  setScreenshotSource(data.evidence?.screenshot_data_url || (data.evidence?.screenshot ? `/${String(data.evidence.screenshot).replace(/^\//, '')}` : ''));
}

async function pollJob(jobId) {
  if (pollTimer) clearInterval(pollTimer);

  const tick = async () => {
    try {
      const resp = await fetch(`/api/analyze/status/${jobId}`);
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.detail || 'Status lookup failed');

      setStatus(data.progress || 0, data.message || 'Working', data.status !== 'done' && data.status !== 'error');

      if (data.status === 'done') {
        clearInterval(pollTimer);
        pollTimer = null;
        renderResult(data.result);
        setBusy(false);
        statusText.textContent = 'Analysis complete';
        statusNote.textContent = 'Results are locked in until you run a new analysis.';
        progressText.textContent = '100%';
        progressFill.style.width = '100%';
      } else if (data.status === 'error') {
        clearInterval(pollTimer);
        pollTimer = null;
        throw new Error(data.error || 'Analysis failed');
      }
    } catch (err) {
      clearInterval(pollTimer);
      pollTimer = null;
      summaryEl.innerHTML = `<span class="error">${err.message}</span>`;
      reasonsEl.innerHTML = '<span class="tag">Run failed</span>';
      setBusy(false);
      statusText.textContent = 'Analysis failed';
      statusNote.textContent = err.message;
    }
  };

  await tick();
  pollTimer = setInterval(tick, 650);
}

async function analyze(formData) {
  setStatus(8, 'Submitting request', true);
  try {
    const resp = await fetch('/api/analyze/start', {
      method: 'POST',
      body: formData,
    });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) {
      throw new Error(data.detail || data.error || 'Analysis failed');
    }
    activeJob = data.job_id;
    statusText.textContent = 'Analysis started';
    statusNote.textContent = 'Browser capture and enrichment are in progress.';
    await pollJob(activeJob);
  } catch (err) {
    summaryEl.innerHTML = `<span class="error">${err.message}</span>`;
    reasonsEl.innerHTML = '<span class="tag">Run failed</span>';
    statusText.textContent = 'Analysis failed';
    statusNote.textContent = err.message;
    setBusy(false);
  }
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(form);
  fd.set('timeout_ms', document.getElementById('timeout_ms').value);
  fd.set('max_images', document.getElementById('max_images').value);
  await analyze(fd);
});

document.querySelectorAll('[data-sample]').forEach((btn) => {
  btn.addEventListener('click', () => {
    const sample = btn.getAttribute('data-sample');
    document.getElementById('url').value = `${window.location.origin}${sample}`;
    document.getElementById('brand_name').value = sample.includes('phish') ? 'Demo Bank' : 'Example Corp';
    document.getElementById('official_domain').value = sample.includes('phish') ? 'demobank.com' : 'example.com';
    statusText.textContent = 'Sample loaded';
    statusNote.textContent = 'Press Analyze URL to inspect the sample page.';
  });
});

renderBars({ phishing: 0, brand: 0, threat_intel: 0, infrastructure: 0 });
setRing(0);
setIdleState();

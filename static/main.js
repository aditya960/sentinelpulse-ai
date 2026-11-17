// ==============================
// static/main.js
// ==============================
/*
   Front‑end logic for SentinelPulse AI.
   Uses fetch to talk to Flask JSON APIs, updates DOM, and renders Chart.js charts.
*/

// ----- GLOBAL STATE ---------------------------------------------------
let threatData = [];
let lineChart;
let copilotHistory = [];
let hasCurrentAssessment = false;

// ----- UTILITIES ------------------------------------------------------
function $(id) { return document.getElementById(id); }

function fetchJson(url, options = {}) {
    return fetch(url, options).then(r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
    });
}

function updateKPIs() {
    fetchJson('/api/kpis')
        .then(data => {
            $('kpi-total-logs').textContent = data.total_logs;
            $('kpi-active-critical').textContent = data.active_critical;
            $('kpi-mitigated').textContent = data.mitigated;
            $('kpi-health-score').textContent = data.health_score + '%';
        })
        .catch(console.error);
}

function renderThreatTable() {
    const tbody = $('threatTableBody');
    tbody.innerHTML = '';
    const filter = $('severityFilter').value;
    const search = $('searchBox').value.toLowerCase();
    threatData.forEach(log => {
        if (filter !== 'All' && log.severity !== filter) return;
        if (search && !log.source_ip.includes(search) && !log.attack_type.toLowerCase().includes(search)) return;
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td class="p-2">${log.timestamp}</td>
            <td class="p-2">${log.source_ip}</td>
            <td class="p-2">${log.attack_type}</td>
            <td class="p-2">${log.mitre_id}</td>
            <td class="p-2"><span class="px-2 py-1 rounded ${severityClass(log.severity)}">${log.severity}</span></td>
            <td class="p-2"><span class="px-2 py-1 rounded ${statusClass(log.status)}">${log.status}</span></td>
            <td class="p-2">
                ${log.status === 'Active' ? `<button class="mitigate-btn bg-emerald-600 hover:bg-emerald-500 text-white py-1 px-2 rounded" data-id="${log.id}">Mitigate</button>` : ''}
            </td>
        `;
        tbody.appendChild(tr);
    });
    if (!tbody.children.length) {
        const tr = document.createElement('tr');
        const td = document.createElement('td');
        td.colSpan = 7;
        td.className = 'empty-feed';
        td.textContent = threatData.length ? 'No incidents match these filters.' : 'No incidents yet. Reset the demo or simulate an attack to add events.';
        tr.appendChild(td);
        tbody.appendChild(tr);
    }
    // Attach mitigation handlers
    document.querySelectorAll('.mitigate-btn').forEach(btn => {
        btn.addEventListener('click', () => mitigateThreat(parseInt(btn.dataset.id)));
    });
}

function severityClass(sev) {
    switch (sev) {
        case 'Critical': return 'bg-red-600 text-white';
        case 'High': return 'bg-orange-600 text-white';
        case 'Medium': return 'bg-yellow-600 text-white';
        case 'Low': return 'bg-green-600 text-white';
        default: return 'bg-gray-600 text-white';
    }
}
function statusClass(st) {
    return st === 'Active' ? 'bg-red-600 text-white' : 'bg-green-600 text-white';
}

function loadThreats() {
    fetchJson('/api/threats')
        .then(data => {
            threatData = data;
            $('activityRange').addEventListener('change', updateCharts);
            renderThreatTable();
            updateCharts();
            updateForecast();
        })
        .catch(console.error);
}

function mitigateThreat(id) {
    fetchJson('/api/mitigate', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({id})})
        .then(() => {
            // Update local copy
            const log = threatData.find(l => l.id === id);
            if (log) log.status = 'Mitigated';
            markAssessmentStale();
            renderThreatTable();
            updateKPIs();
            updateCharts();
            updateForecast();
        })
        .catch(console.error);
}

// ----- CHARTS ----------------------------------------------------------
function initCharts() {
    const lineCtx = $('lineChart').getContext('2d');
    lineChart = new Chart(lineCtx, {
        type: 'line',
        data: { labels: [], datasets: [] },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            devicePixelRatio: Math.max(window.devicePixelRatio || 1, 2),
            animation: false,
            interaction: { mode: 'index', intersect: false },
            elements: { line: { borderWidth: 2.5 }, point: { radius: 2, hoverRadius: 5, borderWidth: 1.5 } },
            plugins: { legend: { display: true, labels: { color: chartTextColor(), usePointStyle: true, boxWidth: 8 } } },
            scales: {
                x: { ticks: { color: chartTextColor(), maxRotation: 0 }, grid: { color: chartGridColor() } },
                y: { type: 'linear', position: 'left', ticks: { color: chartTextColor() }, grid: { color: chartGridColor() }, beginAtZero: true },
                critical: { type: 'linear', position: 'right', ticks: { color: chartTextColor(), precision: 0 }, grid: { drawOnChartArea: false }, beginAtZero: true, suggestedMax: 5 }
            },
            onHover: (event, activeElements) => {
                event.native.target.style.cursor = activeElements.length ? 'crosshair' : 'default';
            },
            onClick: (event, activeElements) => {
                if (!activeElements.length) return;
                lineChart.setActiveElements(activeElements.map(({datasetIndex, index}) => ({datasetIndex, index})));
                lineChart.tooltip.setActiveElements(activeElements.map(({datasetIndex, index}) => ({datasetIndex, index})), {x: event.x, y: event.y});
                lineChart.update('none');
            }
        }
    });
}

function chartTextColor() { return document.body.classList.contains('dark-theme') ? '#b8bfcd' : '#4b5563'; }
function chartGridColor() { return document.body.classList.contains('dark-theme') ? '#303440' : '#e5e7eb'; }

function updateChartTheme() {
    if (!lineChart) return;
    const text = chartTextColor();
    const grid = chartGridColor();
    lineChart.options.plugins.legend.labels.color = text;
    for (const axis of Object.values(lineChart.options.scales)) {
        axis.ticks.color = text;
        axis.grid.color = grid;
    }
    lineChart.update('none');
}

function updateCharts() {
    const hours = Number($('activityRange').value);
    fetchJson(`/api/analytics/activity?hours=${hours}`)
        .then(data => {
            const gradient = lineChart.ctx.createLinearGradient(0, 0, 0, lineChart.height);
            gradient.addColorStop(0, document.body.classList.contains('dark-theme') ? 'rgba(79,140,255,.28)' : 'rgba(37,99,235,.16)');
            gradient.addColorStop(1, 'rgba(79,140,255,0)');
            lineChart.data = {
                labels: data.labels,
                datasets: [
                    { label: 'Threat Events', data: data.events, yAxisID: 'y', borderColor: '#4f8cff', backgroundColor: gradient, borderWidth: 2.5, pointRadius: 2.5, tension: 0.25, fill: true },
                    { label: 'Critical Events', data: data.critical, yAxisID: 'critical', borderColor: '#fb5574', backgroundColor: '#fb5574', borderWidth: 2.5, pointRadius: 3, pointHoverRadius: 6, tension: 0.2, fill: false },
                ]
            };
            lineChart.update('none');
        })
        .catch(error => console.error('Could not load threat activity:', error));
}

function updateForecast() {
    const content = $('forecastContent');
    fetchJson('/api/analytics/forecast')
        .then(data => {
            $('forecastConfidence').textContent = `${data.confidence} confidence`;
            content.replaceChildren();

            const top = document.createElement('div');
            top.className = 'forecast-top';
            const score = document.createElement('div');
            const scoreValue = document.createElement('div');
            scoreValue.className = 'forecast-score';
            scoreValue.textContent = `${data.risk_score} / 100`;
            const riskLevel = document.createElement('div');
            riskLevel.className = 'forecast-level';
            riskLevel.textContent = `${data.risk_level} outlook`;
            score.append(scoreValue, riskLevel);
            const drivers = document.createElement('div');
            drivers.className = 'forecast-drivers';
            data.drivers.forEach(text => {
                const line = document.createElement('div');
                line.textContent = `• ${text}`;
                drivers.appendChild(line);
            });
            top.append(score, drivers);
            content.appendChild(top);

            const metrics = document.createElement('div');
            metrics.className = 'forecast-metrics';
            [
                ['Expected events · 6h', data.expected_events],
                ['Most seen attack', data.likely_attack || 'No recent events'],
                ['Events analyzed · 24h', data.type_sample_count],
            ].forEach(([label, value]) => {
                const item = document.createElement('div');
                item.className = 'forecast-metric';
                const caption = document.createElement('div');
                caption.className = 'forecast-metric-label';
                caption.textContent = label;
                const result = document.createElement('div');
                result.className = 'forecast-metric-value';
                result.textContent = value;
                item.append(caption, result);
                metrics.appendChild(item);
            });
            content.appendChild(metrics);

            const bars = document.createElement('div');
            bars.className = 'forecast-bars';
            const max = Math.max(1, ...data.hourly_projection);
            data.hourly_projection.forEach((value, index) => {
                const wrap = document.createElement('div');
                wrap.className = 'forecast-bar-wrap';
                const bar = document.createElement('div');
                bar.className = 'forecast-bar';
                bar.style.height = `${Math.max(5, value / max * 46)}px`;
                bar.title = `${value} expected events`;
                const label = document.createElement('span');
                label.textContent = `+${index + 1}h`;
                wrap.append(bar, label);
                bars.appendChild(wrap);
            });
            content.appendChild(bars);
            const note = document.createElement('div');
            note.className = 'forecast-note';
            note.textContent = data.method;
            content.appendChild(note);
        })
        .catch(error => {
            $('forecastConfidence').textContent = 'Unavailable';
            content.textContent = `Could not build forecast: ${error.message}`;
        });
}

// ----- ATTACK SIMULATOR -----------------------------------------------
function attachSimButtons() {
    document.querySelectorAll('.sim-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const type = btn.dataset.type;
            fetchJson('/api/simulate', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({type})})
                .then(newLog => {
                    threatData.push(newLog);
                    markAssessmentStale();
                    renderThreatTable();
                    updateKPIs();
                    updateCharts();
                    updateForecast();
                })
                .catch(console.error);
        });
    });
}

// ----- AI ANALYSIS & COPILOT -----------------------------------------
function requestAI(message, history = []) {
    return fetch('/api/copilot', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({message, history})
    })
        .then(async response => {
            const data = await response.json();
            if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
            return data;
        });
}

function renderAssessment(payload) {
    const root = $('aiBriefResult');
    hasCurrentAssessment = true;
    root.replaceChildren();
    const assessment = payload.assessment;
    const meta = document.createElement('div');
    meta.className = 'brief-meta';
    const risk = document.createElement('span');
    risk.className = `risk-pill risk-${assessment.risk_level.toLowerCase()}`;
    risk.textContent = `${assessment.risk_level} risk`;
    const confidence = document.createElement('span');
    confidence.className = 'confidence-pill';
    confidence.textContent = `${assessment.confidence} confidence`;
    const provider = document.createElement('span');
    provider.className = 'brief-description';
    provider.textContent = `${payload.model} · ${new Date(payload.generated_at).toLocaleTimeString([], {hour: '2-digit', minute: '2-digit'})}`;
    meta.append(risk, confidence, provider);
    const summary = document.createElement('p');
    summary.className = 'brief-summary';
    summary.textContent = assessment.summary;
    root.append(meta, summary);

    if (assessment.priorities.length) {
        const label = document.createElement('div');
        label.className = 'brief-section-label';
        label.textContent = 'Prioritized incidents';
        const grid = document.createElement('div');
        grid.className = 'priority-grid';
        assessment.priorities.forEach(item => {
            const card = document.createElement('article');
            card.className = 'priority-card';
            const event = document.createElement('span');
            event.className = 'priority-event';
            event.textContent = `EVENT #${item.event_id} · ${item.priority}`;
            const title = document.createElement('h3');
            title.textContent = item.title;
            const evidence = document.createElement('p');
            evidence.textContent = item.evidence;
            const mitigation = document.createElement('p');
            mitigation.textContent = `Next step: ${item.mitigation}`;
            const mitre = document.createElement('p');
            mitre.textContent = `MITRE: ${item.mitre_id}`;
            card.append(event, title, evidence, mitre, mitigation);
            grid.appendChild(card);
        });
        root.append(label, grid);
    }
    const gapsLabel = document.createElement('div');
    gapsLabel.className = 'brief-section-label';
    gapsLabel.textContent = 'Evidence gaps';
    const gaps = document.createElement('div');
    gaps.className = 'brief-gaps';
    gaps.textContent = assessment.data_gaps.length ? assessment.data_gaps.join(' · ') : 'No material data gaps reported.';
    root.append(gapsLabel, gaps);
}

function markAssessmentStale() {
    if (!hasCurrentAssessment) return;
    hasCurrentAssessment = false;
    $('aiBriefResult').textContent = 'Threat records changed since this assessment. Run a new analysis for an updated brief.';
}

function askCopilot(prompt) {
    const sendButton = $('sendChat');
    sendButton.disabled = true;
    requestAI(prompt, copilotHistory.slice(-8))
        .then(data => {
            const reply = data.reply || 'The AI service returned an empty response.';
            copilotHistory.push({role: 'user', content: prompt}, {role: 'assistant', content: reply});
            copilotHistory = copilotHistory.slice(-8);
            addChatMessage('Copilot', reply);
        })
        .catch(error => addChatMessage('Copilot', error.message))
        .finally(() => { sendButton.disabled = false; });
}

function runThreatAssessment() {
    const button = $('runAiBrief');
    const result = $('aiBriefResult');
    button.disabled = true;
    button.textContent = 'Analyzing…';
    result.textContent = 'Reviewing severity, recurring sources, attack patterns, and defensive priorities…';
    fetch('/api/ai/assessment', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({})})
        .then(async response => {
            const data = await response.json();
            if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
            return data;
        })
        .then(renderAssessment)
        .then(() => {})
        .catch(error => { result.textContent = error.message; })
        .finally(() => { button.disabled = false; button.textContent = 'Analyze threats'; });
}

function loadCopilotStatus() {
    const status = $('aiApiStatus');
    fetchJson('/api/copilot/status')
        .then(data => {
            status.classList.toggle('ready', data.configured);
            status.classList.toggle('missing', !data.configured);
            const provider = data.provider || 'AI';
            status.textContent = data.configured ? `${provider} · ${data.model}` : `${provider} key required`;
            status.title = data.configured ? `${provider} API key is configured on the server` : `Set the ${provider} API key on the server to enable AI responses`;
        })
        .catch(() => {
            status.classList.add('missing');
            status.textContent = 'AI API unavailable';
        });
}

function addChatMessage(sender, text) {
    const log = $('chatLog');
    $('chatWelcome')?.remove();
    const message = document.createElement('div');
    const isUser = sender === 'You';
    message.className = `chat-message${isUser ? ' user' : ''}`;
    const avatar = document.createElement('span');
    avatar.className = 'chat-avatar';
    avatar.textContent = isUser ? '●' : '✦';
    const bubble = document.createElement('div');
    bubble.className = 'message-bubble';
    const content = document.createElement('div');
    content.textContent = text;
    const time = document.createElement('div');
    time.className = 'message-time';
    time.textContent = new Date().toLocaleTimeString([], {hour: '2-digit', minute: '2-digit'});
    bubble.append(content, time);
    if (isUser) message.append(bubble, avatar);
    else message.append(avatar, bubble);
    log.appendChild(message);
    log.scrollTop = log.scrollHeight;
}

function initCopilot() {
    // Quick‑question buttons
    document.querySelectorAll('.quick-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const q = btn.dataset.q;
            let prompt = '';
            if (q === 'critical') prompt = 'show critical threats';
            else if (q === 'dangerous_ip') prompt = 'which IP is most dangerous?';
            else if (q === 'suggestion') prompt = 'suggest mitigation steps';
            else if (q === 'summary') prompt = 'summarize the indicators of compromise';
            else if (q === 'timeline') prompt = 'build a timeline from the threat events';
            else if (q === 'lateral') prompt = 'identify signs of lateral movement';
            else if (q === 'mitre') prompt = 'map the observed attacks to MITRE ATT&CK';
            addChatMessage('You', prompt);
            askCopilot(prompt);
        });
    });
    // Custom input
    const send = () => {
        const input = $('chatInput');
        const txt = input.value.trim();
        if (!txt) return;
        addChatMessage('You', txt);
        askCopilot(txt);
        input.value = '';
    };
    $('sendChat').addEventListener('click', send);
    $('chatInput').addEventListener('keydown', event => {
        if (event.key === 'Enter' && !event.shiftKey) { event.preventDefault(); send(); }
    });
    $('clearChatBtn')?.addEventListener('click', () => {
        copilotHistory = [];
        $('chatLog').replaceChildren();
        const welcome = document.createElement('div');
        welcome.id = 'chatWelcome';
        welcome.className = 'chat-welcome';
        welcome.textContent = 'I can summarize alerts, compare indicators, and suggest defensive next steps based on the current feed.';
        $('chatLog').appendChild(welcome);
    });
}

// ----- EXPORT ----------------------------------------------------------
$('exportBtn').addEventListener('click', () => {
    // Trigger download of CSV via the Flask endpoint
    window.location.href = '/api/export';
});

$('clearFeedBtn').addEventListener('click', () => {
    if (!threatData.length || !window.confirm('Clear all threat feed records?')) return;
    fetchJson('/api/threats', {method: 'DELETE'})
        .then(() => {
            threatData = [];
            markAssessmentStale();
            renderThreatTable();
            updateKPIs();
            updateCharts();
            updateForecast();
        })
        .catch(console.error);
});

$('resetDemoBtn').addEventListener('click', () => {
    if (!window.confirm('Restore the original demo incidents? Current incidents will be replaced.')) return;
    fetchJson('/api/demo/reset', {method: 'POST'})
        .then(data => {
            threatData = data.threats;
            hasCurrentAssessment = false;
            $('severityFilter').value = 'All';
            $('searchBox').value = '';
            $('aiBriefResult').replaceChildren(document.createTextNode('Demo data restored. Run an assessment to review these events.'));
            renderThreatTable();
            updateKPIs();
            updateCharts();
            updateForecast();
        })
        .catch(error => window.alert(error.message));
});

// ----- THEME ----------------------------------------------------------
function initThemeToggle() {
    const savedTheme = localStorage.getItem('sentinelpulse-theme');
    document.body.classList.toggle('dark-theme', savedTheme !== 'light');
    document.body.classList.toggle('light-theme', savedTheme === 'light');
    $('themeToggle').textContent = document.body.classList.contains('dark-theme') ? 'Light theme' : 'Dark theme';
    $('themeToggle').setAttribute('aria-pressed', String(document.body.classList.contains('dark-theme')));
    updateChartTheme();
    $('themeToggle').addEventListener('click', () => {
        const enabled = document.body.classList.toggle('dark-theme');
        document.body.classList.toggle('light-theme', !enabled);
        $('themeToggle').textContent = enabled ? 'Light theme' : 'Dark theme';
        $('themeToggle').setAttribute('aria-pressed', String(enabled));
        localStorage.setItem('sentinelpulse-theme', enabled ? 'dark' : 'light');
        updateChartTheme();
    });
}

// ----- INITIALISATION -------------------------------------------------
window.addEventListener('DOMContentLoaded', () => {
    initCharts();
    loadThreats();
    updateKPIs();
    updateForecast();
    attachSimButtons();
    initCopilot();
    $('runAiBrief').addEventListener('click', runThreatAssessment);
    loadCopilotStatus();
    initThemeToggle();
    // Filters & search
    $('severityFilter').addEventListener('change', renderThreatTable);
    $('searchBox').addEventListener('input', renderThreatTable);
});

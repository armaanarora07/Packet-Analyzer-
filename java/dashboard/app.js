/**
 * Packet Analyzer & DPI Engine - Dashboard JavaScript
 * Consumes /api/stats and /api/flows via fetch() and updates the DOM.
 */

// Global state
let currentFlows = [];

document.addEventListener('DOMContentLoaded', () => {
    initDashboard();
});

function initDashboard() {
    const btnRefresh = document.getElementById('btn-refresh');
    const flowSearchInput = document.getElementById('flow-search-input');

    if (btnRefresh) {
        btnRefresh.addEventListener('click', () => {
            fetchDashboardData();
        });
    }

    if (flowSearchInput) {
        flowSearchInput.addEventListener('input', (e) => {
            filterFlowsTable(e.target.value);
        });
    }

    // Initial load
    fetchDashboardData();

    // Auto-refresh poll every 5 seconds
    setInterval(fetchDashboardData, 5000);
}

/**
 * Fetches data from both REST endpoints concurrently and updates the UI.
 */
async function fetchDashboardData() {
    try {
        const [statsRes, flowsRes] = await Promise.all([
            fetch('/api/stats'),
            fetch('/api/flows')
        ]);

        if (!statsRes.ok || !flowsRes.ok) {
            throw new Error(`API error: stats=${statsRes.status}, flows=${flowsRes.status}`);
        }

        const statsData = await statsRes.json();
        const flowsData = await flowsRes.json();

        hideError();
        updateConnectionStatus(true);
        updateSummaryCards(statsData);
        updateAppDistribution(statsData.applicationDistribution || {});
        updateSecuritySection(statsData);

        currentFlows = flowsData || [];
        const searchVal = document.getElementById('flow-search-input')?.value || '';
        renderFlowsTable(currentFlows, searchVal);

        updateLastRefreshedTime();
    } catch (err) {
        console.error('Failed to load DPI dashboard data:', err);
        showError('Unable to connect to DPI REST API. Ensure the Java engine server is running.');
        updateConnectionStatus(false);
    }
}

/**
 * Updates summary cards with latest counters.
 */
function updateSummaryCards(stats) {
    setText('val-total-packets', formatNumber(stats.totalPackets || 0));
    setText('val-total-bytes', formatBytes(stats.totalBytes || 0) + ' total');
    setText('val-forwarded-packets', formatNumber(stats.forwardedPackets || 0));
    setText('val-dropped-packets', formatNumber(stats.droppedPackets || 0));

    const dropRate = (stats.dropRatePercent !== undefined) ? stats.dropRatePercent : 0;
    setText('val-drop-rate', `${dropRate.toFixed(2)}% drop rate`);

    setText('val-active-flows', formatNumber(stats.activeFlows || 0));
    setText('val-tcp-packets', formatNumber(stats.tcpPackets || 0));
    setText('val-udp-packets', formatNumber(stats.udpPackets || 0));
}

/**
 * Renders the CSS-based application distribution progress bars.
 */
function updateAppDistribution(appDist) {
    const container = document.getElementById('app-distribution-container');
    const badge = document.getElementById('classified-flow-count');
    if (!container) return;

    const entries = Object.entries(appDist);
    if (badge) {
        badge.textContent = `${entries.length} applications`;
    }

    if (entries.length === 0) {
        container.innerHTML = '<div class="loading-state">No classified applications yet.</div>';
        return;
    }

    // Sort descending by count
    entries.sort((a, b) => b[1] - a[1]);

    const total = entries.reduce((acc, curr) => acc + curr[1], 0);

    let html = '';
    for (const [app, count] of entries) {
        const pct = total > 0 ? ((count / total) * 100).toFixed(1) : '0.0';
        html += `
            <div class="app-bar-item">
                <div class="app-bar-meta">
                    <span class="app-name">${escapeHtml(app)}</span>
                    <span class="app-count">${count} flows (${pct}%)</span>
                </div>
                <div class="bar-track">
                    <div class="bar-fill" style="width: ${pct}%;"></div>
                </div>
            </div>
        `;
    }

    container.innerHTML = html;
}

/**
 * Updates the Traffic and Security Policy overview section.
 */
function updateSecuritySection(stats) {
    const total = stats.totalPackets || 0;
    const fwd = stats.forwardedPackets || 0;
    const drop = stats.droppedPackets || 0;
    const dropRate = (stats.dropRatePercent !== undefined) ? stats.dropRatePercent : 0;

    setText('sec-forwarded', `${formatNumber(fwd)} pkts`);
    setText('sec-dropped', `${formatNumber(drop)} pkts`);
    setText('sec-drop-rate', `${dropRate.toFixed(2)}%`);

    const fwdPct = total > 0 ? (fwd / total) * 100 : 100;
    const dropPct = total > 0 ? (drop / total) * 100 : 0;

    const barFwd = document.getElementById('sec-bar-forwarded');
    const barDrop = document.getElementById('sec-bar-dropped');

    if (barFwd) barFwd.style.width = `${fwdPct}%`;
    if (barDrop) barDrop.style.width = `${dropPct}%`;
}

/**
 * Renders the Active Flows data table with search filtering.
 */
function renderFlowsTable(flows, filterText = '') {
    const tbody = document.getElementById('flows-table-body');
    const countLabel = document.getElementById('flow-table-count');
    if (!tbody) return;

    const lowerFilter = (filterText || '').trim().toLowerCase();
    const filtered = flows.filter(flow => {
        if (!lowerFilter) return true;
        return (
            (flow.srcIp && flow.srcIp.toLowerCase().includes(lowerFilter)) ||
            (flow.dstIp && flow.dstIp.toLowerCase().includes(lowerFilter)) ||
            (flow.application && flow.application.toLowerCase().includes(lowerFilter)) ||
            (flow.sni && flow.sni.toLowerCase().includes(lowerFilter)) ||
            (flow.protocol && flow.protocol.toLowerCase().includes(lowerFilter)) ||
            String(flow.srcPort).includes(lowerFilter) ||
            String(flow.dstPort).includes(lowerFilter)
        );
    });

    if (countLabel) {
        countLabel.textContent = `Showing ${filtered.length} of ${flows.length} flows`;
    }

    if (filtered.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="8" class="text-center loading-state">
                    ${flows.length === 0 ? 'No active network flows recorded.' : 'No flows match the search filter.'}
                </td>
            </tr>
        `;
        return;
    }

    let rowsHtml = '';
    for (const flow of filtered) {
        const protoBadgeClass = flow.protocol === 'TCP' ? 'badge-tcp' : 'badge-udp';
        const actionBadgeClass = flow.action === 'DROP' ? 'badge-blocked' : 'badge-forward';

        rowsHtml += `
            <tr>
                <td><strong>${escapeHtml(flow.srcIp)}</strong>:${flow.srcPort}</td>
                <td><strong>${escapeHtml(flow.dstIp)}</strong>:${flow.dstPort}</td>
                <td><span class="table-badge ${protoBadgeClass}">${escapeHtml(flow.protocol)}</span></td>
                <td>
                    <strong>${escapeHtml(flow.application)}</strong>
                    ${flow.sni ? `<span class="flow-sni-sub">${escapeHtml(flow.sni)}</span>` : ''}
                </td>
                <td class="text-right">${formatNumber(flow.packetCount)}</td>
                <td class="text-right">${formatBytes(flow.bytes)}</td>
                <td><span class="status-badge" style="font-size: 0.7rem; padding: 0.1rem 0.4rem;">${escapeHtml(flow.state)}</span></td>
                <td><span class="table-badge ${actionBadgeClass}">${escapeHtml(flow.action)}</span></td>
            </tr>
        `;
    }

    tbody.innerHTML = rowsHtml;
}

function filterFlowsTable(filterText) {
    renderFlowsTable(currentFlows, filterText);
}

// Helpers
function setText(id, text) {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
}

function formatNumber(num) {
    return new Intl.NumberFormat().format(num);
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function escapeHtml(str) {
    if (!str) return '';
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function updateConnectionStatus(connected) {
    const el = document.getElementById('connection-status');
    if (!el) return;
    if (connected) {
        el.className = 'status-badge status-connected';
        el.innerHTML = '<span class="status-dot"></span> Live';
    } else {
        el.className = 'status-badge status-error';
        el.innerHTML = '<span class="status-dot"></span> Offline';
    }
}

function updateLastRefreshedTime() {
    const el = document.getElementById('last-updated');
    if (el) {
        const now = new Date();
        el.textContent = `Updated ${now.toLocaleTimeString()}`;
    }
}

function showError(msg) {
    const banner = document.getElementById('error-banner');
    const msgEl = document.getElementById('error-message');
    if (banner && msgEl) {
        msgEl.textContent = msg;
        banner.classList.remove('alert-hidden');
    }
}

function hideError() {
    const banner = document.getElementById('error-banner');
    if (banner) {
        banner.classList.add('alert-hidden');
    }
}

/**
 * SCAMSHIELD 360 - Main Application Controller
 * Detect. Explain. Protect.
 * 
 * Handles SPA tab routing, dashboard statistics synchronization,
 * scan history management, and expo demo quick-actions.
 */

(function (window) {
  'use strict';

  window.App = {
    currentTab: 'dashboard',
    switchTab,
    refreshDashboard,
    refreshHistory
  };

  document.addEventListener('DOMContentLoaded', initApp);

  function initApp() {
    initNavigation();
    initHistoryControls();
    refreshDashboard();
    refreshHistory();
  }

  /**
   * SPA Navigation Handler
   */
  function initNavigation() {
    const navButtons = document.querySelectorAll('.nav-btn');
    navButtons.forEach(btn => {
      btn.addEventListener('click', (e) => {
        const targetTab = e.currentTarget.getAttribute('data-tab');
        if (targetTab) {
          switchTab(targetTab);
        }
      });
    });

    // Quick launch cards on dashboard
    document.querySelectorAll('.quick-launch-card').forEach(card => {
      card.addEventListener('click', (e) => {
        const targetTab = e.currentTarget.getAttribute('data-tab');
        if (targetTab) {
          switchTab(targetTab);
        }
      });
    });
  }

  function switchTab(tabId) {
    window.App.currentTab = tabId;

    // Update active state in nav buttons
    document.querySelectorAll('.nav-btn').forEach(btn => {
      if (btn.getAttribute('data-tab') === tabId) {
        btn.classList.add('active');
      } else {
        btn.classList.remove('active');
      }
    });

    // Show/hide sections
    document.querySelectorAll('.page-section').forEach(sec => {
      if (sec.id === `section-${tabId}`) {
        sec.classList.add('active');
      } else {
        sec.classList.remove('active');
      }
    });

    // Specific refreshes
    if (tabId === 'dashboard') {
      refreshDashboard();
    } else if (tabId === 'history') {
      refreshHistory();
    }

    // Scroll main viewport to top
    const mainContent = document.querySelector('.main-content');
    if (mainContent) mainContent.scrollTop = 0;
  }

  /**
   * Dashboard Statistics & Recent Scans
   */
  function refreshDashboard() {
    if (!window.ThreatEngine) return;

    const stats = window.ThreatEngine.getStats();
    const history = window.ThreatEngine.getHistory();

    // Stat cards
    setText('stat-total-scans', stats.total);
    setText('stat-threats-detected', stats.threats);
    setText('stat-safe-results', stats.safe);
    setText('stat-avg-score', `${stats.avgScore}/100`);

    // Distribution Bars
    const total = Math.max(1, stats.total);
    setBarWidth('dist-bar-safe', Math.round((stats.distribution.low / total) * 100));
    setBarWidth('dist-bar-medium', Math.round((stats.distribution.medium / total) * 100));
    setBarWidth('dist-bar-high', Math.round((stats.distribution.high / total) * 100));
    setBarWidth('dist-bar-critical', Math.round((stats.distribution.critical / total) * 100));

    setText('dist-count-safe', `${stats.distribution.low} scans`);
    setText('dist-count-medium', `${stats.distribution.medium} scans`);
    setText('dist-count-high', `${stats.distribution.high} scans`);
    setText('dist-count-critical', `${stats.distribution.critical} scans`);

    // Recent Scans Table (top 5)
    renderRecentTable(history.slice(0, 5));
  }

  function renderRecentTable(items) {
    const tbody = document.getElementById('recent-scans-tbody');
    if (!tbody) return;

    if (!items || items.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="5" style="text-align: center; color: var(--text-dim); padding: 24px;">
            No scan activities recorded yet. Run a scan from the sidebar to populate live metrics.
          </td>
        </tr>
      `;
      return;
    }

    tbody.innerHTML = items.map(item => {
      const timeFormatted = formatTimeAgo(item.scannedAt);
      const snippet = item.input.length > 55 ? item.input.substring(0, 55) + '...' : item.input;

      return `
        <tr>
          <td><span class="channel-pill ${item.type}">${item.type.toUpperCase()}</span></td>
          <td class="target-cell" title="${escapeHtml(item.input)}">${escapeHtml(snippet)}</td>
          <td><span class="badge ${item.badgeClass}">${item.riskScore}/100</span></td>
          <td><span class="badge ${item.badgeClass}">${item.classification}</span></td>
          <td style="color: var(--text-dim); font-size: 0.8rem;">${timeFormatted}</td>
        </tr>
      `;
    }).join('');
  }

  /**
   * Scan History Table, Search & Filters
   */
  function initHistoryControls() {
    const searchInput = document.getElementById('history-search-input');
    const typeFilter = document.getElementById('history-type-filter');
    const riskFilter = document.getElementById('history-risk-filter');
    const clearBtn = document.getElementById('clear-history-btn');
    const exportBtn = document.getElementById('export-history-btn');

    if (searchInput) {
      searchInput.addEventListener('input', refreshHistory);
    }
    if (typeFilter) {
      typeFilter.addEventListener('change', refreshHistory);
    }
    if (riskFilter) {
      riskFilter.addEventListener('change', refreshHistory);
    }

    if (clearBtn) {
      clearBtn.addEventListener('click', () => {
        if (confirm('Are you sure you want to clear all scan history records?')) {
          window.ThreatEngine.clearHistory();
          refreshHistory();
          refreshDashboard();
        }
      });
    }

    if (exportBtn) {
      exportBtn.addEventListener('click', exportHistoryAsJson);
    }
  }

  function refreshHistory() {
    if (!window.ThreatEngine) return;

    const allHistory = window.ThreatEngine.getHistory();
    const searchInput = document.getElementById('history-search-input');
    const typeFilter = document.getElementById('history-type-filter');
    const riskFilter = document.getElementById('history-risk-filter');
    const tbody = document.getElementById('history-scans-tbody');

    if (!tbody) return;

    const query = searchInput ? searchInput.value.trim().toLowerCase() : '';
    const typeVal = typeFilter ? typeFilter.value : 'all';
    const riskVal = riskFilter ? riskFilter.value : 'all';

    const filtered = allHistory.filter(item => {
      // Type filter
      if (typeVal !== 'all' && item.type !== typeVal) return false;

      // Risk filter
      if (riskVal === 'safe' && item.riskScore > 30) return false;
      if (riskVal === 'suspicious' && (item.riskScore <= 30 || item.riskScore > 60)) return false;
      if (riskVal === 'phishing' && item.riskScore <= 60) return false;

      // Search query
      if (query) {
        const matchInput = item.input.toLowerCase().includes(query);
        const matchClass = item.classification.toLowerCase().includes(query);
        const matchLevel = item.riskLevel.toLowerCase().includes(query);
        if (!matchInput && !matchClass && !matchLevel) return false;
      }

      return true;
    });

    const countElem = document.getElementById('history-total-count');
    if (countElem) countElem.textContent = `${filtered.length} records`;

    if (filtered.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="6" style="text-align: center; color: var(--text-dim); padding: 32px;">
            No scan logs match your current filter parameters.
          </td>
        </tr>
      `;
      return;
    }

    tbody.innerHTML = filtered.map(item => {
      const dateObj = new Date(item.scannedAt);
      const timeFormatted = dateObj.toLocaleDateString() + ' ' + dateObj.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      const snippet = item.input.length > 60 ? item.input.substring(0, 60) + '...' : item.input;

      return `
        <tr>
          <td style="color: var(--text-dim); font-size: 0.82rem;">${timeFormatted}</td>
          <td><span class="channel-pill ${item.type}">${item.type.toUpperCase()}</span></td>
          <td class="target-cell" title="${escapeHtml(item.input)}">${escapeHtml(snippet)}</td>
          <td><span class="badge ${item.badgeClass}">${item.riskScore}/100</span></td>
          <td><span class="badge ${item.badgeClass}">${item.classification}</span></td>
          <td style="font-size: 0.8rem; color: var(--text-muted); max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
            ${escapeHtml(item.recommendation)}
          </td>
        </tr>
      `;
    }).join('');
  }

  function exportHistoryAsJson() {
    const history = window.ThreatEngine.getHistory();
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(history, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `scamshield360_scan_history_${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  }



  // Helpers
  function setText(id, text) {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
  }

  function setBarWidth(id, percent) {
    const el = document.getElementById(id);
    if (el) el.style.width = `${Math.min(100, Math.max(0, percent))}%`;
  }

  function formatTimeAgo(isoString) {
    try {
      const now = Date.now();
      const past = new Date(isoString).getTime();
      const diffSec = Math.floor((now - past) / 1000);

      if (diffSec < 60) return 'Just now';
      if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
      if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
      return `${Math.floor(diffSec / 86400)}d ago`;
    } catch (e) {
      return 'Recently';
    }
  }

  function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/[&<>"']/g, function (m) {
      switch (m) {
        case '&': return '&amp;';
        case '<': return '&lt;';
        case '>': return '&gt;';
        case '"': return '&quot;';
        case "'": return '&#039;';
        default: return m;
      }
    });
  }

})(window);

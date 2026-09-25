/**
 * SCAMSHIELD 360 - URL Scanner Module
 * Detect. Explain. Protect.
 */

(function () {
  'use strict';

  document.addEventListener('DOMContentLoaded', initUrlScanner);

  function initUrlScanner() {
    const urlInput = document.getElementById('url-input');
    const analyzeBtn = document.getElementById('analyze-url-btn');
    const resultCard = document.getElementById('url-result-card');
    const errorBox = document.getElementById('url-error-msg');

    if (!analyzeBtn || !urlInput) return;

    analyzeBtn.addEventListener('click', () => {
      runUrlAnalysis(urlInput.value);
    });

    urlInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        runUrlAnalysis(urlInput.value);
      }
    });

  }

  function runUrlAnalysis(url) {
    const urlInput = document.getElementById('url-input');
    const resultCard = document.getElementById('url-result-card');
    const errorBox = document.getElementById('url-error-msg');

    if (!url || !url.trim()) {
      showError('Please enter a URL to analyze.');
      return;
    }

    hideError();

    // Visual button loading state
    const analyzeBtn = document.getElementById('analyze-url-btn');
    const originalText = analyzeBtn.innerHTML;
    analyzeBtn.innerHTML = '<span>⚡ Analyzing Heuristics...</span>';
    analyzeBtn.disabled = true;

    setTimeout(() => {
      // Deterministic Threat Engine Analysis
      const result = window.ThreatEngine.analyzeUrl(url);

      analyzeBtn.innerHTML = originalText;
      analyzeBtn.disabled = false;

      if (!result.isValid) {
        showError(result.error);
        return;
      }

      // Save to history & trigger dashboard refresh
      window.ThreatEngine.saveScan(result);
      if (window.App && typeof window.App.refreshDashboard === 'function') {
        window.App.refreshDashboard();
      }

      // Render Results
      renderUrlResult(result);
    }, 280);
  }

  function renderUrlResult(result) {
    const resultCard = document.getElementById('url-result-card');
    resultCard.style.display = 'block';
    resultCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

    // Target text
    document.getElementById('url-target-display').textContent = result.input;

    // Classification & Badge
    const classElem = document.getElementById('url-verdict-class');
    classElem.textContent = result.classification;
    classElem.className = 'verdict-classification ' + result.badgeClass;

    const riskLevelElem = document.getElementById('url-risk-level');
    riskLevelElem.textContent = `${result.riskLevel} (${result.riskScore}/100)`;
    riskLevelElem.className = 'badge ' + result.badgeClass;

    // Score Meter / Gauge Animation
    animateGauge('url-gauge-fill', 'url-score-number', result.riskScore);

    // Render "Why this was detected" indicators
    const indicatorsContainer = document.getElementById('url-indicators-list');
    indicatorsContainer.innerHTML = '';

    result.indicators.forEach(ind => {
      const item = document.createElement('div');
      item.className = 'indicator-item';

      const iconClass = ind.severity === 'safe' ? 'safe' : (ind.severity === 'critical' ? 'critical' : 'warning');
      const deltaText = ind.scoreDelta > 0 ? `+${ind.scoreDelta} Risk` : `Safe`;

      item.innerHTML = `
        <span class="indicator-icon">${ind.icon}</span>
        <div class="indicator-content">
          <div class="indicator-title">${escapeHtml(ind.title)}</div>
          <div class="indicator-detail">${escapeHtml(ind.detail)}</div>
        </div>
        <span class="indicator-delta badge ${ind.severity}">${deltaText}</span>
      `;
      indicatorsContainer.appendChild(item);
    });

    // Recommended Action
    const recBox = document.getElementById('url-recommendation-box');
    const recText = document.getElementById('url-recommendation-text');
    recText.textContent = result.recommendation;

    if (result.riskScore >= 61) {
      recBox.className = 'recommendation-box critical';
    } else {
      recBox.className = 'recommendation-box';
    }
  }

  function animateGauge(circleId, numberId, targetScore) {
    const circle = document.getElementById(circleId);
    const numDisplay = document.getElementById(numberId);

    // 2 * PI * r (r=45) = ~283
    const circumference = 283;
    const offset = circumference - (targetScore / 100) * circumference;

    let strokeColor = '#10b981'; // safe green
    if (targetScore > 80) strokeColor = '#ef4444'; // critical red
    else if (targetScore > 60) strokeColor = '#f97316'; // high orange
    else if (targetScore > 30) strokeColor = '#f59e0b'; // medium amber

    if (circle) {
      circle.style.stroke = strokeColor;
      circle.style.strokeDashoffset = offset;
    }

    if (numDisplay) {
      let current = 0;
      const step = Math.max(1, Math.floor(targetScore / 20));
      const interval = setInterval(() => {
        current += step;
        if (current >= targetScore) {
          current = targetScore;
          clearInterval(interval);
        }
        numDisplay.textContent = current;
      }, 20);
    }
  }

  function showError(msg) {
    const errorBox = document.getElementById('url-error-msg');
    if (errorBox) {
      errorBox.textContent = msg;
      errorBox.style.display = 'block';
    }
  }

  function hideError() {
    const errorBox = document.getElementById('url-error-msg');
    if (errorBox) {
      errorBox.style.display = 'none';
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

})();

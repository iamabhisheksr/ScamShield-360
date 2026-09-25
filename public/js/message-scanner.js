/**
 * SCAMSHIELD 360 - Message Scanner Module
 * Detect. Explain. Protect.
 */

(function () {
  'use strict';

  document.addEventListener('DOMContentLoaded', initMessageScanner);

  function initMessageScanner() {
    const msgTextarea = document.getElementById('message-input');
    const analyzeBtn = document.getElementById('analyze-msg-btn');
    const clearBtn = document.getElementById('clear-msg-btn');
    const charCounter = document.getElementById('msg-char-count');

    if (!analyzeBtn || !msgTextarea) return;

    // Character counter
    msgTextarea.addEventListener('input', () => {
      const len = msgTextarea.value.length;
      const words = msgTextarea.value.trim().split(/\s+/).filter(Boolean).length;
      if (charCounter) {
        charCounter.textContent = `${len} characters | ${words} words`;
      }
    });

    analyzeBtn.addEventListener('click', () => {
      runMessageAnalysis(msgTextarea.value);
    });

    if (clearBtn) {
      clearBtn.addEventListener('click', () => {
        msgTextarea.value = '';
        if (charCounter) charCounter.textContent = '0 characters | 0 words';
        document.getElementById('msg-result-card').style.display = 'none';
        hideError();
      });
    }

  }

  function runMessageAnalysis(text) {
    const msgTextarea = document.getElementById('message-input');
    const resultCard = document.getElementById('msg-result-card');
    const errorBox = document.getElementById('msg-error-msg');

    if (!text || !text.trim()) {
      showError('Please paste or type message content to analyze.');
      return;
    }

    hideError();

    // Visual button loading state
    const analyzeBtn = document.getElementById('analyze-msg-btn');
    const originalText = analyzeBtn.innerHTML;
    analyzeBtn.innerHTML = '<span>⚡ Analyzing NLP Patterns...</span>';
    analyzeBtn.disabled = true;

    setTimeout(() => {
      // Analyze with Threat Engine
      const result = window.ThreatEngine.analyzeMessage(text);

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
      renderMessageResult(result);
    }, 280);
  }

  function renderMessageResult(result) {
    const resultCard = document.getElementById('msg-result-card');
    resultCard.style.display = 'block';
    resultCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

    // Target snippet
    const snippet = result.input.length > 120 ? result.input.substring(0, 120) + '...' : result.input;
    document.getElementById('msg-target-display').textContent = `"${snippet}"`;

    // Classification & Badge
    const classElem = document.getElementById('msg-verdict-class');
    classElem.textContent = result.classification;
    classElem.className = 'verdict-classification ' + result.badgeClass;

    const riskLevelElem = document.getElementById('msg-risk-level');
    riskLevelElem.textContent = `${result.riskLevel} (${result.riskScore}/100)`;
    riskLevelElem.className = 'badge ' + result.badgeClass;

    // Score Meter / Gauge Animation
    animateGauge('msg-gauge-fill', 'msg-score-number', result.riskScore);

    // Render "Why this was detected" indicators
    const indicatorsContainer = document.getElementById('msg-indicators-list');
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
    const recBox = document.getElementById('msg-recommendation-box');
    const recText = document.getElementById('msg-recommendation-text');
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

    const circumference = 283;
    const offset = circumference - (targetScore / 100) * circumference;

    let strokeColor = '#10b981';
    if (targetScore > 80) strokeColor = '#ef4444';
    else if (targetScore > 60) strokeColor = '#f97316';
    else if (targetScore > 30) strokeColor = '#f59e0b';

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
    const errorBox = document.getElementById('msg-error-msg');
    if (errorBox) {
      errorBox.textContent = msg;
      errorBox.style.display = 'block';
    }
  }

  function hideError() {
    const errorBox = document.getElementById('msg-error-msg');
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

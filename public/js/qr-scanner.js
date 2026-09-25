/**
 * SCAMSHIELD 360 - QR Code Scanner Module
 * Detect. Explain. Protect.
 * 
 * Pipeline:
 * QR Image / Camera Frame -> Local jsQR Decoder -> Extract URL/Text -> Threat Engine -> Explainable Breakdown
 */

(function () {
  'use strict';

  let cameraStream = null;
  let animationFrameId = null;
  let isScanningCamera = false;

  document.addEventListener('DOMContentLoaded', initQrScanner);

  function initQrScanner() {
    const fileInput = document.getElementById('qr-file-input');
    const uploadZone = document.getElementById('qr-upload-zone');
    const startCameraBtn = document.getElementById('start-camera-btn');
    const stopCameraBtn = document.getElementById('stop-camera-btn');

    if (!uploadZone) return;

    // File Input change
    if (fileInput) {
      fileInput.addEventListener('change', (e) => {
        if (e.target.files && e.target.files[0]) {
          handleQrFile(e.target.files[0]);
        }
      });
    }

    // Drag and drop
    uploadZone.addEventListener('dragover', (e) => {
      e.preventDefault();
      uploadZone.classList.add('dragover');
    });

    uploadZone.addEventListener('dragleave', () => {
      uploadZone.classList.remove('dragover');
    });

    uploadZone.addEventListener('drop', (e) => {
      e.preventDefault();
      uploadZone.classList.remove('dragover');
      if (e.dataTransfer.files && e.dataTransfer.files[0]) {
        handleQrFile(e.dataTransfer.files[0]);
      }
    });

    uploadZone.addEventListener('click', (e) => {
      // Don't trigger if clicked on preview
      if (e.target.closest('.qr-preview-area')) return;
      if (fileInput) fileInput.click();
    });

    // Camera buttons
    if (startCameraBtn) {
      startCameraBtn.addEventListener('click', startCamera);
    }
    if (stopCameraBtn) {
      stopCameraBtn.addEventListener('click', stopCamera);
    }
  }

  /**
   * Handle user uploaded image file
   */
  function handleQrFile(file) {
    if (!file.type.startsWith('image/')) {
      showError('Please upload an image file (PNG, JPG, WebP).');
      return;
    }

    const reader = new FileReader();
    reader.onload = function (event) {
      const img = new Image();
      img.onload = function () {
        showPreview(event.target.result);
        decodeQrFromImage(img);
      };
      img.src = event.target.result;
    };
    reader.readAsDataURL(file);
  }

  /**
   * Load and decode sample image from URL path
   */
  function loadAndDecodeImageFromUrl(imgPath) {
    hideError();
    const img = new Image();
    img.crossOrigin = 'anonymous';
    img.onload = function () {
      showPreview(imgPath);
      decodeQrFromImage(img);
    };
    img.onerror = function () {
      showError(`Unable to load sample QR image from ${imgPath}.`);
    };
    img.src = imgPath;
  }

  function showPreview(dataUrl) {
    const previewArea = document.getElementById('qr-preview-area');
    const previewImg = document.getElementById('qr-preview-img');
    const promptArea = document.getElementById('qr-upload-prompt');

    if (previewArea && previewImg) {
      previewImg.src = dataUrl;
      previewArea.style.display = 'flex';
      if (promptArea) promptArea.style.display = 'none';
    }
  }

  /**
   * Core QR decoding using client-side jsQR library
   */
  function decodeQrFromImage(img) {
    hideError();

    if (typeof window.jsQR !== 'function') {
      showError('QR Decoder library is loading or unavailable.');
      return;
    }

    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    canvas.width = img.naturalWidth || img.width;
    canvas.height = img.naturalHeight || img.height;

    ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);

    const code = window.jsQR(imageData.data, imageData.width, imageData.height, {
      inversionAttempts: 'attemptBoth'
    });

    if (code && code.data) {
      processExtractedContent(code.data);
    } else {
      showError('No valid QR code could be detected in the provided image. Please ensure the QR is clear and well-lit.');
    }
  }

  /**
   * Pipeline Step: Process Extracted Content via Explainable Threat Engine
   */
  function processExtractedContent(rawContent) {
    const trimmed = rawContent.trim();
    let result;

    // Check if URL or message text
    const isLikelyUrl = /^(https?:\/\/|[a-zA-Z0-9-]+\.[a-zA-Z]{2,})/i.test(trimmed);

    if (isLikelyUrl) {
      result = window.ThreatEngine.analyzeUrl(trimmed);
      result.type = 'qr';
    } else {
      result = window.ThreatEngine.analyzeMessage(trimmed);
      result.type = 'qr';
    }

    // Save to history & trigger dashboard update
    window.ThreatEngine.saveScan(result);
    if (window.App && typeof window.App.refreshDashboard === 'function') {
      window.App.refreshDashboard();
    }

    renderQrResult(result);
  }

  function renderQrResult(result) {
    const resultCard = document.getElementById('qr-result-card');
    resultCard.style.display = 'block';
    resultCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

    // Decoded payload text
    document.getElementById('qr-target-display').textContent = result.input;

    // Classification & Badge
    const classElem = document.getElementById('qr-verdict-class');
    classElem.textContent = result.classification;
    classElem.className = 'verdict-classification ' + result.badgeClass;

    const riskLevelElem = document.getElementById('qr-risk-level');
    riskLevelElem.textContent = `${result.riskLevel} (${result.riskScore}/100)`;
    riskLevelElem.className = 'badge ' + result.badgeClass;

    // Score Meter / Gauge Animation
    animateGauge('qr-gauge-fill', 'qr-score-number', result.riskScore);

    // Indicators list
    const indicatorsContainer = document.getElementById('qr-indicators-list');
    indicatorsContainer.innerHTML = '';

    // Add QR extraction origin indicator
    const qrOriginItem = document.createElement('div');
    qrOriginItem.className = 'indicator-item';
    qrOriginItem.innerHTML = `
      <span class="indicator-icon">📷</span>
      <div class="indicator-content">
        <div class="indicator-title">QR Code Decoded Successfully</div>
        <div class="indicator-detail">Extracted destination: <code>${escapeHtml(result.input)}</code>. Forwarded through explainable heuristic engine.</div>
      </div>
      <span class="indicator-delta badge safe">Verified</span>
    `;
    indicatorsContainer.appendChild(qrOriginItem);

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

    // Recommendation
    const recBox = document.getElementById('qr-recommendation-box');
    const recText = document.getElementById('qr-recommendation-text');
    recText.textContent = result.recommendation;

    if (result.riskScore >= 61) {
      recBox.className = 'recommendation-box critical';
    } else {
      recBox.className = 'recommendation-box';
    }
  }

  /**
   * Live Camera Scanner Handling
   */
  async function startCamera() {
    hideError();
    const videoContainer = document.getElementById('qr-video-container');
    const video = document.getElementById('qr-video');
    const startBtn = document.getElementById('start-camera-btn');
    const stopBtn = document.getElementById('stop-camera-btn');

    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      showError('Live camera API is not supported in this browser environment. Please upload a QR code image to analyze.');
      return;
    }

    try {
      cameraStream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: 'environment' }
      });
      video.srcObject = cameraStream;
      video.setAttribute('playsinline', true);
      await video.play();

      videoContainer.style.display = 'block';
      startBtn.style.display = 'none';
      stopBtn.style.display = 'inline-flex';
      isScanningCamera = true;

      requestAnimationFrame(scanCameraFrame);
    } catch (err) {
      console.warn('Camera permission denied or camera not found:', err);
      showError('Camera access unavailable or permission was denied. Please upload a QR code image to analyze.');
    }
  }

  function scanCameraFrame() {
    if (!isScanningCamera) return;

    const video = document.getElementById('qr-video');
    if (video.readyState === video.HAVE_ENOUGH_DATA) {
      const canvas = document.createElement('canvas');
      canvas.width = video.videoWidth;
      canvas.height = video.videoHeight;
      const ctx = canvas.getContext('2d');
      ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);

      if (typeof window.jsQR === 'function') {
        const code = window.jsQR(imageData.data, imageData.width, imageData.height, {
          inversionAttempts: 'attemptBoth'
        });

        if (code && code.data) {
          stopCamera();
          processExtractedContent(code.data);
          return;
        }
      }
    }

    animationFrameId = requestAnimationFrame(scanCameraFrame);
  }

  function stopCamera() {
    isScanningCamera = false;
    if (animationFrameId) cancelAnimationFrame(animationFrameId);

    if (cameraStream) {
      cameraStream.getTracks().forEach(track => track.stop());
      cameraStream = null;
    }

    const videoContainer = document.getElementById('qr-video-container');
    const startBtn = document.getElementById('start-camera-btn');
    const stopBtn = document.getElementById('stop-camera-btn');

    if (videoContainer) videoContainer.style.display = 'none';
    if (startBtn) startBtn.style.display = 'inline-flex';
    if (stopBtn) stopBtn.style.display = 'none';
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
    const errorBox = document.getElementById('qr-error-msg');
    if (errorBox) {
      errorBox.textContent = msg;
      errorBox.style.display = 'block';
    }
  }

  function hideError() {
    const errorBox = document.getElementById('qr-error-msg');
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

  // Global helper for demo bar
  window.scanDemoQr = function (sampleName) {
    loadAndDecodeImageFromUrl(`assets/qr-samples/${sampleName}`);
  };

})();

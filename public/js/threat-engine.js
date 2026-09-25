/**
 * SCAMSHIELD 360 - Explainable Threat Analysis Engine (Client Side)
 * Detect. Explain. Protect.
 */

(function (window) {
  'use strict';

  const LEGITIMATE_BRAND_DOMAINS = {
    paypal: ['paypal.com', 'paypal.me'],
    google: ['google.com', 'accounts.google.com', 'support.google.com', 'google.co.in'],
    microsoft: ['microsoft.com', 'live.com', 'login.microsoftonline.com', 'outlook.com'],
    apple: ['apple.com', 'icloud.com', 'appleid.apple.com'],
    amazon: ['amazon.com', 'amazon.in', 'amazon.co.uk'],
    netflix: ['netflix.com'],
    facebook: ['facebook.com', 'fb.com', 'meta.com'],
    instagram: ['instagram.com'],
    whatsapp: ['whatsapp.com'],
    sbi: ['onlinesbi.sbi', 'sbi.co.in'],
    hdfc: ['hdfcbank.com'],
    icici: ['icicibank.com'],
    binance: ['binance.com'],
    metamask: ['metamask.io'],
    chase: ['chase.com'],
    wellsfargo: ['wellsfargo.com'],
    fedex: ['fedex.com'],
    dhl: ['dhl.com']
  };

  const SUSPICIOUS_TLDS = [
    '.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', 
    '.buzz', '.cam', '.work', '.click', '.rest', '.fit',
    '.link', '.live', '.loan', '.surf', '.vip', '.icu',
    '.support', '.country', '.stream', '.kim', '.download'
  ];

  const KNOWN_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'ow.ly', 
    'cutt.ly', 'shorturl.at', 'rb.gy', 'soo.gd', 'tiny.cc'
  ];

  const SUSPICIOUS_URL_KEYWORDS = [
    'login', 'signin', 'verify', 'verification', 'account', 'banking', 
    'secure', 'security', 'update', 'wallet', 'kyc', 'billing', 
    'confirm', 'confirmation', 'authenticate', 'credential', 'recovery',
    'password', 'auth', 'claim', 'refund', 'unlock', 'unusual-activity'
  ];

  /**
   * Deterministic URL Threat Analysis
   */
  function analyzeUrl(rawUrl) {
    if (!rawUrl || typeof rawUrl !== 'string' || !rawUrl.trim()) {
      return {
        isValid: false,
        error: 'Please enter a valid URL to analyze.'
      };
    }

    const trimmedUrl = rawUrl.trim();
    const hasScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmedUrl);
    let parsedUrl;

    try {
      parsedUrl = new URL(hasScheme ? trimmedUrl : `http://${trimmedUrl}`);
    } catch (e) {
      return {
        isValid: false,
        error: 'Malformed URL structure. Please provide a standard URL format.'
      };
    }

    const protocol = parsedUrl.protocol.toLowerCase();
    const hostname = parsedUrl.hostname.toLowerCase();
    const pathname = parsedUrl.pathname.toLowerCase();
    const search = parsedUrl.search.toLowerCase();
    const fullHref = parsedUrl.href;
    const fullText = (hostname + pathname + search).toLowerCase();

    const indicators = [];
    let riskScore = 0;

    // 1. Protocol Check (HTTPS vs HTTP)
    if (protocol === 'https:') {
      indicators.push({
        id: 'HTTPS_ACTIVE',
        severity: 'safe',
        icon: '✓',
        title: 'HTTPS Encryption Active',
        detail: 'Connection uses SSL/TLS encryption. (Note: Phishing sites can also install free SSL certificates, so domain heuristics are evaluated next).',
        scoreDelta: 0
      });
    } else if (protocol === 'http:') {
      riskScore += 25;
      indicators.push({
        id: 'NO_HTTPS',
        severity: 'danger',
        icon: '⚠',
        title: 'Insecure Protocol (HTTP Only)',
        detail: 'Website does not use encrypted HTTPS. Modern financial and authentication portals strictly require HTTPS.',
        scoreDelta: 25
      });
    }

    // 2. IP Address in Hostname
    const isIpAddress = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname) || (hostname.startsWith('[') && hostname.endsWith(']'));
    if (isIpAddress) {
      riskScore += 45;
      indicators.push({
        id: 'IP_HOSTNAME',
        severity: 'critical',
        icon: '🚨',
        title: 'Raw IP Address Used Instead of Domain',
        detail: `The URL directly connects to an IP address (${hostname}) instead of a registered domain name. This is a common evasion technique in phishing attacks.`,
        scoreDelta: 45
      });
    }

    // 3. '@' Symbol in URL
    if (trimmedUrl.includes('@')) {
      riskScore += 45;
      indicators.push({
        id: 'AT_SYMBOL',
        severity: 'critical',
        icon: '🚨',
        title: 'Deceptive "@" Symbol Detected',
        detail: 'The "@" character instructs browsers to ignore everything preceding it and only navigate to what follows, tricking users into seeing a fake target.',
        scoreDelta: 45
      });
    }

    // 4. URL Length Evaluation
    if (fullHref.length > 75) {
      riskScore += 20;
      indicators.push({
        id: 'LONG_URL',
        severity: 'warning',
        icon: '⚠',
        title: 'Abnormally Long URL Length (>75 chars)',
        detail: `URL has ${fullHref.length} characters. Attackers frequently use long strings to hide deceptive domains or pass encoded payload tokens.`,
        scoreDelta: 20
      });
    } else if (fullHref.length > 54) {
      riskScore += 10;
      indicators.push({
        id: 'MODERATE_LONG_URL',
        severity: 'warning',
        icon: 'ℹ',
        title: 'Elevated URL Length (>54 chars)',
        detail: `URL length is ${fullHref.length} characters, somewhat higher than standard navigation links.`,
        scoreDelta: 10
      });
    }

    // 5. Excessive Subdomains
    const domainParts = hostname.split('.');
    const cleanParts = domainParts.filter(p => p !== 'www');
    if (cleanParts.length > 3) {
      const penalty = cleanParts.length >= 5 ? 30 : 20;
      riskScore += penalty;
      indicators.push({
        id: 'EXCESSIVE_SUBDOMAINS',
        severity: penalty >= 30 ? 'critical' : 'danger',
        icon: '🚨',
        title: `Excessive Subdomain Levels (${cleanParts.length} parts)`,
        detail: `Complex domain structure "${hostname}" often indicates subdomain spoofing to disguise the real root domain from mobile viewers.`,
        scoreDelta: penalty
      });
    }

    // 6. Suspicious TLD Detection
    const matchedTld = SUSPICIOUS_TLDS.find(tld => hostname.endsWith(tld));
    if (matchedTld) {
      riskScore += 25;
      indicators.push({
        id: 'SUSPICIOUS_TLD',
        severity: 'danger',
        icon: '⚠',
        title: `High-Risk Top Level Domain (${matchedTld})`,
        detail: `The domain uses "${matchedTld}", a TLD frequently leveraged by bulk phishing kits due to low registration barriers and weak abuse monitoring.`,
        scoreDelta: 25
      });
    }

    // 7. URL Shortener Detection
    const matchedShortener = KNOWN_SHORTENERS.find(s => hostname === s || hostname.endsWith('.' + s));
    if (matchedShortener) {
      riskScore += 25;
      indicators.push({
        id: 'URL_SHORTENER',
        severity: 'warning',
        icon: '⚠',
        title: `URL Shortener Masking Destination (${matchedShortener})`,
        detail: 'This is a shortened URL. The ultimate destination domain is hidden, preventing immediate verification of target authenticity.',
        scoreDelta: 25
      });
    }

    // 8. Excessive Hyphens in Hostname
    const hyphenCount = (hostname.match(/-/g) || []).length;
    if (hyphenCount >= 3) {
      riskScore += 30;
      indicators.push({
        id: 'EXCESSIVE_HYPHENS',
        severity: 'critical',
        icon: '🚨',
        title: `Excessive Hyphenation (${hyphenCount} hyphens in domain)`,
        detail: 'Legitimate corporate domains rarely string multiple hyphenated words together. Attackers use hyphens to mimic legitimate brands (e.g., paypal-security-login).',
        scoreDelta: 30
      });
    } else if (hyphenCount >= 2) {
      riskScore += 15;
      indicators.push({
        id: 'MODERATE_HYPHENS',
        severity: 'warning',
        icon: '⚠',
        title: `Multiple Hyphens in Hostname (${hyphenCount} hyphens)`,
        detail: 'Hyphenated domain names are frequently used in brand spoofing variations.',
        scoreDelta: 15
      });
    }

    // 9. Brand Impersonation Check
    let brandImpersonated = null;
    for (const [brand, legitDomains] of Object.entries(LEGITIMATE_BRAND_DOMAINS)) {
      if (hostname.includes(brand) || fullText.includes(brand)) {
        const isLegit = legitDomains.some(legit => hostname === legit || hostname.endsWith('.' + legit));
        if (!isLegit) {
          brandImpersonated = brand;
          riskScore += 45;
          indicators.push({
            id: 'BRAND_IMPERSONATION',
            severity: 'critical',
            icon: '🚨',
            title: `Possible Brand Impersonation: "${brand.toUpperCase()}"`,
            detail: `The URL references official brand "${brand}" inside "${hostname}", but is NOT hosted on any authorized ${brand} infrastructure (${legitDomains.join(', ')}).`,
            scoreDelta: 45
          });
          break;
        }
      }
    }

    // 10. Suspicious Login & Security Keywords
    const foundKeywords = SUSPICIOUS_URL_KEYWORDS.filter(kw => fullText.includes(kw));
    if (foundKeywords.length > 0) {
      let kwPenalty = foundKeywords.length === 1 ? 20 : 35 + (foundKeywords.length - 2) * 10;
      kwPenalty = Math.min(kwPenalty, 50);
      riskScore += kwPenalty;
      indicators.push({
        id: 'CREDENTIAL_KEYWORDS',
        severity: foundKeywords.length >= 2 ? 'danger' : 'warning',
        icon: '⚠',
        title: `Suspicious Security/Login Keywords: [${foundKeywords.slice(0, 4).join(', ')}]`,
        detail: `Contains sensitive verification terms (${foundKeywords.join(', ')}). Attackers frequently bundle "secure" and "login" keywords in subdomains to trick victims into entering passwords.`,
        scoreDelta: kwPenalty
      });
    }

    // 11. Punycode / Homoglyph check
    if (hostname.includes('xn--')) {
      riskScore += 35;
      indicators.push({
        id: 'PUNYCODE_HOMOGLYPH',
        severity: 'critical',
        icon: '🚨',
        title: 'Punycode / Homoglyph Attack Detected (xn--)',
        detail: 'The domain uses internationalized punycode characters to visually spoof ASCII Latin characters (e.g., Cyrillic "а" instead of Latin "a").',
        scoreDelta: 35
      });
    }

    // 12. Non-standard Web Port Check
    if (parsedUrl.port && parsedUrl.port !== '80' && parsedUrl.port !== '443') {
      riskScore += 20;
      indicators.push({
        id: 'SUSPICIOUS_PORT',
        severity: 'warning',
        icon: '⚠',
        title: `Non-Standard Web Port (Port :${parsedUrl.port})`,
        detail: `Running web traffic on non-standard port :${parsedUrl.port} is often seen in rogue servers, staging phishing kits, or compromised web hosts.`,
        scoreDelta: 20
      });
    }

    // Default Clean Indicator
    if (riskScore === 0) {
      indicators.push({
        id: 'STANDARD_STRUCTURE',
        severity: 'safe',
        icon: '✓',
        title: 'Standard Domain & Path Structure',
        detail: 'No deceptive keywords, excessive hyphens, or spoofing patterns were detected in the URL structure.',
        scoreDelta: 0
      });
    }

    // Final Capping
    riskScore = Math.min(Math.max(riskScore, 0), 100);

    let classification = 'SAFE';
    let riskLevel = 'LOW RISK';
    let badgeClass = 'risk-low';
    let recommendation = 'Proceed with normal caution. The URL parameters and structure appear standard.';

    if (riskScore >= 81) {
      classification = 'PHISHING';
      riskLevel = 'CRITICAL';
      badgeClass = 'risk-critical';
      recommendation = 'DO NOT OPEN OR ENTER CREDENTIALS! This link displays strong indicators of fraudulent brand impersonation or credential theft.';
    } else if (riskScore >= 61) {
      classification = 'PHISHING';
      riskLevel = 'HIGH RISK';
      badgeClass = 'risk-high';
      recommendation = 'Avoid entering personal or financial information. High likelihood of deceptive domain routing.';
    } else if (riskScore >= 31) {
      classification = 'SUSPICIOUS';
      riskLevel = 'MEDIUM RISK';
      badgeClass = 'risk-medium';
      recommendation = 'Verify the website before continuing. Confirm the exact domain directly in your browser address bar.';
    }

    return {
      isValid: true,
      type: 'url',
      input: rawUrl,
      parsed: {
        protocol,
        hostname,
        pathname,
        search,
        port: parsedUrl.port || (protocol === 'https:' ? '443' : '80')
      },
      riskScore,
      riskLevel,
      classification,
      badgeClass,
      indicators,
      recommendation,
      features: {
        urlLength: fullHref.length,
        isHttps: protocol === 'https:',
        isIpAddress,
        hasAtSymbol: trimmedUrl.includes('@'),
        subdomainCount: cleanParts.length,
        suspiciousTld: matchedTld || null,
        isShortener: !!matchedShortener,
        hyphenCount,
        brandImpersonated,
        suspiciousKeywords: foundKeywords
      },
      scannedAt: new Date().toISOString()
    };
  }

  /**
   * Deterministic Message Threat Analysis
   */
  function analyzeMessage(rawText) {
    if (!rawText || typeof rawText !== 'string' || !rawText.trim()) {
      return {
        isValid: false,
        error: 'Please enter message content to analyze.'
      };
    }

    const text = rawText.trim();
    const lower = text.toLowerCase();
    const indicators = [];
    let riskScore = 0;

    // 1. Prize / Reward / Lottery Scam
    const prizePatterns = [
      'congratulations', 'congrats', 'you have won', 'you won', 'won ₹', 'won rs', 
      'lottery', 'lucky draw', 'reward', 'rewards', 'claim your reward', 'cashback', 
      'claim your prize', 'selected winner', 'gift voucher', 'jackpot'
    ];
    const foundPrize = prizePatterns.filter(p => lower.includes(p));
    if (foundPrize.length > 0) {
      riskScore += 30;
      indicators.push({
        id: 'PRIZE_REWARD_SCAM',
        severity: 'critical',
        icon: '🚨',
        title: 'Prize/reward scam',
        detail: 'Message lures the recipient with unsolicited winnings or lottery prizes to lower psychological defenses.',
        scoreDelta: 30
      });
    }

    // 2. Urgency
    const urgencyPatterns = [
      'immediately', 'urgent', 'urgently', 'hurry', 'within 24 hours', 'within 2 hours', 
      'suspended today', 'act now', 'limited time', 'expires today', 'final notice', 
      'last warning', 'blocked today', 'immediate effect', 'right now'
    ];
    const foundUrgency = urgencyPatterns.filter(p => lower.includes(p));
    if (foundUrgency.length > 0) {
      riskScore += 24;
      indicators.push({
        id: 'URGENCY',
        severity: 'critical',
        icon: '🚨',
        title: 'Urgency',
        detail: 'Creates artificial time pressure ("immediately") to force hasty action before the victim can verify authenticity.',
        scoreDelta: 24
      });
    }

    // 3. Financial Manipulation
    const financialPatterns = [
      '₹', 'rs.', 'rs ', 'inr', '50,000', 'dollars', '$', 'cash', 'money', 'claim your reward',
      'bank account', 'processing fee', 'transfer amount', 'double your money', 'credit', 'debit'
    ];
    const foundFinancial = financialPatterns.filter(p => lower.includes(p));
    if (foundFinancial.length > 0) {
      riskScore += 20;
      indicators.push({
        id: 'FINANCIAL_MANIPULATION',
        severity: 'critical',
        icon: '🚨',
        title: 'Financial manipulation',
        detail: 'References specific currency amounts or monetary promises designed to exploit financial greed or fear.',
        scoreDelta: 20
      });
    }

    // 4. Suspicious Call-to-Action
    const ctaPatterns = [
      'click immediately', 'click this link', 'click link', 'click here', 'tap here', 'tap this link',
      'claim', 'claim reward', 'claim now', 'download apk', 'install apk', 'anydesk', 'teamviewer',
      'open link', 'verify using the link', 'link below'
    ];
    const foundCta = ctaPatterns.filter(p => lower.includes(p));
    if (foundCta.length > 0) {
      riskScore += 20;
      indicators.push({
        id: 'SUSPICIOUS_CTA',
        severity: 'critical',
        icon: '🚨',
        title: 'Suspicious call-to-action',
        detail: 'Pushes user directly toward an unverified link or action under coercive or baiting pretext.',
        scoreDelta: 20
      });
    }

    // 5. Sensitive OTP & Credential Requests
    const credentialPatterns = [
      'otp', 'one time password', 'share otp', 'send otp', 'enter pin', 'upi pin', 
      'password', 'cvv', 'card number', 'atm pin', 'verification code', 'secret code',
      'security code', 'credential', 'share your code'
    ];
    const foundCredentials = credentialPatterns.filter(p => lower.includes(p));
    if (foundCredentials.length > 0) {
      riskScore += 40;
      indicators.push({
        id: 'CREDENTIAL_HARVEST',
        severity: 'critical',
        icon: '🚨',
        title: 'Sensitive Credential / OTP Request',
        detail: `Explicitly requests or references sensitive authentication credentials [${foundCredentials.join(', ')}]. Legitimate financial institutions and companies NEVER request OTPs or PINs via message.`,
        scoreDelta: 40
      });
    }

    // 6. Bank / Account Threats & KYC Expiry
    const bankThreatPatterns = [
      'account will be blocked', 'account blocked', 'debit card blocked', 'card frozen', 
      'kyc expired', 'update kyc', 'kyc verification', 'pan card', 'electricity disconnected', 
      'eb bill', 'unauthorized debit', 'tax refund', 'bank account suspended', 'rbi guideline',
      'sim blocked', 'esim upgrade', 'pending fine', 'challan'
    ];
    const foundBankThreats = bankThreatPatterns.filter(p => lower.includes(p));
    if (foundBankThreats.length > 0) {
      riskScore += 35;
      indicators.push({
        id: 'BANK_THREAT_KYC',
        severity: 'critical',
        icon: '🚨',
        title: 'Bank / Account Threat',
        detail: `Detects banking intimidation tactics [${foundBankThreats.join(', ')}]. Widely documented vectors for unauthorized fund transfers.`,
        scoreDelta: 35
      });
    }

    // 7. Suspicious Job / Part-Time / Crypto Investment Scams
    const jobCryptoPatterns = [
      'part time job', 'earn ₹', 'earn rs', 'daily income', 'work from home', 'telegram task',
      'youtube like', 'review products', 'double your money', 'guaranteed return', 
      'crypto investment', 'vip group'
    ];
    const foundJobCrypto = jobCryptoPatterns.filter(p => lower.includes(p));
    if (foundJobCrypto.length > 0) {
      riskScore += 30;
      indicators.push({
        id: 'JOB_CRYPTO_FRAUD',
        severity: 'danger',
        icon: '⚠',
        title: 'Unrealistic Income / Task Scam Vector',
        detail: `Contains markers of task-based advance-fee fraud [${foundJobCrypto.join(', ')}]. Victims are tricked into small deposits under the guise of high-yield part-time income.`,
        scoreDelta: 30
      });
    }

    // 8. Embedded Links Detection
    const linkRegex = /(https?:\/\/[^\s]+|www\.[^\s]+|[a-zA-Z0-9-]+\.(?:com|xyz|top|me|in|info|co|cc|biz|online|site)[^\s]*)/gi;
    const embeddedLinks = text.match(linkRegex) || [];
    if (embeddedLinks.length > 0) {
      riskScore += 15;
      indicators.push({
        id: 'EMBEDDED_LINKS',
        severity: 'warning',
        icon: '🔗',
        title: `Embedded External Link Detected (${embeddedLinks.length} found)`,
        detail: `Message contains clickable web destinations (${embeddedLinks.slice(0, 2).join(', ')}). In unsolicited messages, external links often route to credential harvesting portals.`,
        scoreDelta: 15
      });
    }

    // Default Clean Indicator
    if (riskScore === 0) {
      indicators.push({
        id: 'NO_SUSPICIOUS_PATTERNS',
        severity: 'safe',
        icon: '✓',
        title: 'No Coercive or Fraudulent Language Patterns',
        detail: 'The message does not contain urgency triggers, credential requests, prize lures, or suspicious remote-tool downloads.',
        scoreDelta: 0
      });
    }

    riskScore = Math.min(Math.max(riskScore, 0), 100);

    let classification = 'SAFE';
    let riskLevel = 'LOW RISK';
    let badgeClass = 'risk-low';
    let recommendation = 'This message appears standard. Always exercise general caution when sharing sensitive personal details.';

    if (riskScore >= 81) {
      classification = 'SCAM';
      riskLevel = 'CRITICAL';
      badgeClass = 'risk-critical';
      recommendation = 'DO NOT CLICK OR PROVIDE PERSONAL INFORMATION. Delete or report this message immediately.';
    } else if (riskScore >= 61) {
      classification = 'SCAM';
      riskLevel = 'HIGH RISK';
      badgeClass = 'risk-high';
      recommendation = 'Avoid interacting with this sender or tapping any embedded links. High probability of financial scam.';
    } else if (riskScore >= 31) {
      classification = 'SUSPICIOUS';
      riskLevel = 'MEDIUM RISK';
      badgeClass = 'risk-medium';
      recommendation = 'Verify authenticity independently through official helpline numbers or banking apps before taking action.';
    }

    return {
      isValid: true,
      type: 'message',
      input: rawText,
      charCount: text.length,
      wordCount: text.split(/\s+/).filter(Boolean).length,
      riskScore,
      riskLevel,
      classification,
      badgeClass,
      indicators,
      recommendation,
      embeddedLinks,
      scannedAt: new Date().toISOString()
    };
  }

  /**
   * Unified Storage Management for History
   */
  const STORAGE_KEY = 'scamshield_scan_history_v1';

  const INITIAL_DEMO_HISTORY = [
    {
      id: 'scan-demo-1',
      type: 'url',
      input: 'https://paypal-login-security.verify-account.example',
      riskScore: 100,
      riskLevel: 'CRITICAL',
      classification: 'PHISHING',
      badgeClass: 'risk-critical',
      recommendation: 'DO NOT OPEN OR ENTER CREDENTIALS!',
      indicatorsCount: 4,
      scannedAt: new Date(Date.now() - 1000 * 60 * 18).toISOString()
    },
    {
      id: 'scan-demo-2',
      type: 'message',
      input: 'Congratulations! You have won ₹50,000. Click immediately to claim your reward.',
      riskScore: 94,
      riskLevel: 'CRITICAL',
      classification: 'SCAM',
      badgeClass: 'risk-critical',
      recommendation: 'DO NOT CLICK OR PROVIDE PERSONAL INFORMATION.',
      indicatorsCount: 4,
      scannedAt: new Date(Date.now() - 1000 * 60 * 45).toISOString()
    },
    {
      id: 'scan-demo-3',
      type: 'url',
      input: 'https://secure-login.example.com',
      riskScore: 35,
      riskLevel: 'MEDIUM RISK',
      classification: 'SUSPICIOUS',
      badgeClass: 'risk-medium',
      recommendation: 'Verify the website before continuing.',
      indicatorsCount: 2,
      scannedAt: new Date(Date.now() - 1000 * 60 * 120).toISOString()
    },
    {
      id: 'scan-demo-4',
      type: 'qr',
      input: 'https://www.google.com',
      riskScore: 0,
      riskLevel: 'LOW RISK',
      classification: 'SAFE',
      badgeClass: 'risk-low',
      recommendation: 'Proceed with normal caution.',
      indicatorsCount: 2,
      scannedAt: new Date(Date.now() - 1000 * 60 * 240).toISOString()
    },
    {
      id: 'scan-demo-5',
      type: 'message',
      input: 'Your bank account will be blocked today. Verify your account immediately using the link below.',
      riskScore: 99,
      riskLevel: 'CRITICAL',
      classification: 'SCAM',
      badgeClass: 'risk-critical',
      recommendation: 'DO NOT CLICK OR PROVIDE PERSONAL INFORMATION.',
      indicatorsCount: 4,
      scannedAt: new Date(Date.now() - 1000 * 60 * 360).toISOString()
    }
  ];

  function getHistory() {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (!stored) {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(INITIAL_DEMO_HISTORY));
        return INITIAL_DEMO_HISTORY;
      }
      return JSON.parse(stored);
    } catch (e) {
      console.warn('LocalStorage unavailable, returning in-memory demo history:', e);
      return INITIAL_DEMO_HISTORY;
    }
  }

  function saveScan(scanResult) {
    if (!scanResult || !scanResult.isValid) return;
    try {
      const history = getHistory();
      const record = {
        id: 'scan-' + Date.now(),
        type: scanResult.type || 'url',
        input: scanResult.input,
        riskScore: scanResult.riskScore,
        riskLevel: scanResult.riskLevel,
        classification: scanResult.classification,
        badgeClass: scanResult.badgeClass,
        recommendation: scanResult.recommendation,
        indicatorsCount: (scanResult.indicators || []).length,
        scannedAt: scanResult.scannedAt || new Date().toISOString()
      };
      history.unshift(record);
      // Keep up to 100 scans
      if (history.length > 100) history.pop();
      localStorage.setItem(STORAGE_KEY, JSON.stringify(history));
      return record;
    } catch (e) {
      console.error('Failed to save scan in history:', e);
    }
  }

  function clearHistory() {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify([]));
    } catch (e) {
      console.error('Failed to clear history:', e);
    }
  }

  function getStats() {
    const history = getHistory();
    const total = history.length;
    let threats = 0;
    let safe = 0;
    let totalScore = 0;

    history.forEach(item => {
      totalScore += item.riskScore;
      if (item.riskScore > 30) {
        threats++;
      } else {
        safe++;
      }
    });

    const avgScore = total > 0 ? Math.round(totalScore / total) : 0;

    // Distribution
    const distribution = {
      low: history.filter(h => h.riskScore <= 30).length,
      medium: history.filter(h => h.riskScore > 30 && h.riskScore <= 60).length,
      high: history.filter(h => h.riskScore > 60 && h.riskScore <= 80).length,
      critical: history.filter(h => h.riskScore > 80).length
    };

    return {
      total,
      threats,
      safe,
      avgScore,
      distribution
    };
  }

  // Export to window
  window.ThreatEngine = {
    analyzeUrl,
    analyzeMessage,
    getHistory,
    saveScan,
    clearHistory,
    getStats
  };

})(window);

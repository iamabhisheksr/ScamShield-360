/**
 * SCAMSHIELD 360 - Node.js / Express Server
 * Detect. Explain. Protect.
 * 
 * College National Level Project Expo Edition
 */

const express = require('express');
const cors = require('cors');
const path = require('path');
const { analyzeUrl, analyzeMessage } = require('./engine/threatEngine');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static frontend assets
app.use(express.static(path.join(__dirname, 'public')));

// In-memory stats counter for server session
let serverStats = {
  totalScans: 0,
  urlScans: 0,
  messageScans: 0,
  threatsDetected: 0,
  safeDetected: 0
};

// API: Health check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ONLINE',
    system: 'SCAMSHIELD 360',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    uptime: Math.floor(process.uptime()) + ' seconds'
  });
});

// API: URL Threat Analysis
app.post('/api/scan/url', (req, res) => {
  const { url } = req.body;
  if (!url) {
    return res.status(400).json({ error: 'URL field is required in request body.' });
  }

  const result = analyzeUrl(url);
  serverStats.totalScans++;
  serverStats.urlScans++;
  if (result.riskScore > 30) {
    serverStats.threatsDetected++;
  } else {
    serverStats.safeDetected++;
  }

  return res.json(result);
});

// API: Message Threat Analysis
app.post('/api/scan/message', (req, res) => {
  const { message } = req.body;
  if (!message) {
    return res.status(400).json({ error: 'Message field is required in request body.' });
  }

  const result = analyzeMessage(message);
  serverStats.totalScans++;
  serverStats.messageScans++;
  if (result.riskScore > 30) {
    serverStats.threatsDetected++;
  } else {
    serverStats.safeDetected++;
  }

  return res.json(result);
});

// API: Global System Stats
app.get('/api/stats', (req, res) => {
  res.json({
    serverStats,
    status: 'OPTIMAL',
    engine: 'Explainable Rule-Based Threat Engine v1.0',
    timestamp: new Date().toISOString()
  });
});

// API: Demo Samples for Judge Demonstration
app.get('/api/demo-samples', (req, res) => {
  res.json({
    urls: [
      {
        name: 'Safe URL',
        url: 'https://www.google.com',
        expectedScore: 0,
        expectedLevel: 'LOW RISK'
      },
      {
        name: 'Suspicious Portal',
        url: 'https://secure-login.example.com',
        expectedScore: 35,
        expectedLevel: 'MEDIUM RISK'
      },
      {
        name: 'Phishing Brand Spoof',
        url: 'https://paypal-login-security.verify-account.example',
        expectedScore: 100,
        expectedLevel: 'CRITICAL'
      }
    ],
    messages: [
      {
        name: 'Prize / Lottery Scam',
        text: 'Congratulations! You have won ₹50,000. Click immediately to claim your reward.',
        expectedScore: 94,
        expectedLevel: 'CRITICAL'
      },
      {
        name: 'Bank KYC Urgent Block',
        text: 'Your bank account will be blocked today. Verify your account immediately using the link below.',
        expectedScore: 99,
        expectedLevel: 'CRITICAL'
      }
    ]
  });
});

// Fallback to index.html for SPA navigation
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start listening
app.listen(PORT, () => {
  console.log('================================================================');
  console.log(`🛡️  SCAMSHIELD 360 Server running at http://localhost:${PORT}`);
  console.log('🛡️  Tagline: Detect. Explain. Protect.');
  console.log('🛡️  Local Rule-Based Explainable Threat Engine Ready');
  console.log('================================================================');
});

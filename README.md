# SCAMSHIELD 360
### *Detect. Explain. Protect.*
**AI-Assisted Multi-Channel Scam & Phishing Detection System**

---

## 🌟 Executive Overview
**SCAMSHIELD 360** is an explainable cybersecurity threat analysis platform built to protect non-technical users and corporate employees from modern social engineering, quishing, and credential phishing attacks.

Rather than acting as a black-box, SCAMSHIELD 360 employs **transparent, explainable heuristics** that not only assign an accurate risk score (0–100) and classification, but explain **WHY** the threat was detected and prescribe **RECOMMENDED ACTIONS**.

---

## 🚀 Quick Start Guide

### Prerequisites
- Node.js (v18+ recommended, tested on Node v24)
- npm

### 1. Installation
In the project directory, run:
```bash
npm install
```

### 2. Launch the Application
```bash
npm start
```
Or with auto-reload during development:
```bash
npm run dev
```

### 3. Open in Browser
Visit:
```
http://localhost:3000
```

---

## 🧭 3-Minute Judge Demonstration Flow

Follow this exact flow during your presentation:

### Step 1: Security Operations Dashboard
- **Action**: Open `http://localhost:3000`.
- **Explain**: *"SCAMSHIELD 360 is an explainable multi-channel threat detection system that monitors URLs, QR codes, and SMS/WhatsApp messages in real time without external API dependencies."*
- **Highlight**: Pre-populated live metrics (Total Scans, Threat Severity Distribution, and Audit Log).

### Step 2: Heuristic URL Scanner
- **Action**: Click **URL Scanner** on the sidebar (or click the top demo bar button: `🚨 Phishing (PayPal Spoof)`).
- **Test URL**:
  ```text
  https://paypal-login-security.verify-account.example
  ```
- **Show Judges**:
  - Risk Score: **100/100 (CRITICAL - PHISHING)**
  - Detailed heuristic badges: Brand Impersonation (`PAYPAL`), High-Risk TLD (`.example`), Excessive Subdomains, Login Keywords.
  - Actionable advice: *"DO NOT OPEN OR ENTER CREDENTIALS!"*
- **Contrast**: Click `Safe: Google` (`https://www.google.com`) -> **Risk Score: 0/100 (LOW RISK - SAFE)**.

### Step 3: Message & SMS Threat Analyzer
- **Action**: Click **Message Scanner** on the sidebar (or click `🚨 Prize Scam (₹50k)` in the demo bar).
- **Test Message**:
  ```text
  Congratulations! You have won ₹50,000. Click immediately to claim your reward.
  ```
- **Show Judges**:
  - Risk Score: **94/100 (CRITICAL - SCAM)**
  - Detected Indicators:
    - 🚨 Prize/reward scam
    - 🚨 Urgency
    - 🚨 Financial manipulation
    - 🚨 Suspicious call-to-action
  - Recommendation: *"DO NOT CLICK OR PROVIDE PERSONAL INFORMATION."*

### Step 4: QR Code Scanner ("Quishing" Defense)
- **Action**: Click **QR Scanner** on the sidebar.
- **Show Judges**:
  - Click on the **Phishing PayPal QR** sample preset (or upload any QR image / start live camera).
  - Watch the pipeline: **QR Image -> Client jsQR Decoder -> Extract Destination -> URL Threat Engine -> Risk Score (100/100)**.
- **Explain**: Demonstrates unified cross-channel pipeline security.

### Step 5: Cyber Awareness ("Can You Detect the Scam?")
- **Action**: Click **Cyber Awareness** on the sidebar.
- **Answer Scenario 1**: Select Option B (`https://google-login-security.verify-account.xyz`).
- **Show Judges**: Immediate forensic breakdown explaining domain hierarchies, TLD abuse, and dynamic awareness score recalculation (100% Cyber Guardian).

---

## 📐 System Architecture

```
                    ┌─────────────────────────┐
                    │      SCAMSHIELD 360     │
                    │ Detect. Explain. Protect│
                    └────────────┬────────────┘
                                 │
         ┌───────────────────────┼──────────────────────┐
         ▼                       ▼                      ▼
   [URL Input]           [Message/SMS Input]       [QR Image / Camera]
         │                       │                      │
         │                       │               jsQR Client Decoder
         │                       │                      │
         └───────────────────────┼──────────────────────┘
                                 ▼
                     ┌───────────────────────┐
                     │   Explainable Threat  │
                     │    Analysis Engine    │
                     └───────────┬───────────┘
                                 │
         ┌───────────────────────┼──────────────────────┐
         ▼                       ▼                      ▼
   [Risk Score]           [Classification]       [Why Detected?]
     (0–100)           SAFE/SUSPICIOUS/PHISHING   Heuristic Badges
                                                        │
                                                        ▼
                                               [Recommended Action]
```

---

## 🧪 Demo Test Data

| Test Category | Input Value | Expected Score | Classification |
|---|---|---|---|
| **Safe URL** | `https://www.google.com` | 0/100 | SAFE (LOW RISK) |
| **Suspicious Portal** | `https://secure-login.example.com` | 35/100 | SUSPICIOUS (MEDIUM RISK) |
| **Phishing Brand Spoof** | `https://paypal-login-security.verify-account.example` | 100/100 | PHISHING (CRITICAL) |
| **Prize Scam SMS** | `"Congratulations! You have won ₹50,000. Click immediately to claim your reward."` | 94/100 | SCAM (CRITICAL) |
| **Bank Block Threat** | `"Your bank account will be blocked today. Verify your account immediately using the link below."` | 99/100 | SCAM (CRITICAL) |

---

## 📁 Repository Structure
```
scamshield360/
├── engine/
│   └── threatEngine.js          # Unified deterministic heuristic engine (Node.js)
├── public/
│   ├── assets/
│   │   └── qr-samples/          # High-resolution test QR code PNGs
│   ├── css/
│   │   └── style.css            # Dark cybersecurity glassmorphism theme
│   ├── js/
│   │   ├── vendor/
│   │   │   └── jsQR.js          # Standalone client-side QR decoder
│   │   ├── threat-engine.js     # Unified deterministic heuristic engine (Browser)
│   │   ├── url-scanner.js       # URL inspection controller
│   │   ├── message-scanner.js   # NLP pattern analyzer controller
│   │   ├── qr-scanner.js        # QR upload, camera & pipeline controller
│   │   ├── awareness.js         # Interactive scam discernment quiz
│   │   └── app.js               # Navigation, stats, and audit log controller
│   └── index.html               # Main application single-page interface
├── scripts/
│   └── generate-demo-qrs.js     # Script to generate sample QR codes
├── server.js                    # Express static server & REST API
├── package.json                 # Project manifest & dependencies
└── README.md                    # Project documentation & presentation guide
```

---

## 🔒 Privacy & Operational Independence
- **100% Offline Capability**: Runs locally on `localhost:3000` without third-party external AI APIs, latency, or paid credentials.
- **Deterministic**: Ensures identical inputs produce identical, defendable scores for judging evaluations.
- **Explainable by Design**: Every point added to the risk score is transparently tied to an observable threat indicator.

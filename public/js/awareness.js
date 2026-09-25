/**
 * SCAMSHIELD 360 - Interactive Cyber Awareness Module
 * "Can You Detect the Scam?"
 * Detect. Explain. Protect.
 */

(function () {
  'use strict';

  const SCENARIOS = [
    {
      id: 1,
      badge: 'Scenario 1: Domain & URL Verification',
      question: 'Which URL is a fraudulent phishing link attempting to harvest Google account credentials?',
      optionA: {
        text: 'https://accounts.google.com',
        isScam: false
      },
      optionB: {
        text: 'https://google-login-security.verify-account.xyz',
        isScam: true
      },
      correctOption: 'B',
      explanation: 'Option B is a malicious phishing domain! The actual registered root domain is "verify-account.xyz" using a high-risk .xyz TLD, while "google-login-security" is merely a spoofed subdomain designed to deceive users. Option A is the official Google authentication domain.'
    },
    {
      id: 2,
      badge: 'Scenario 2: Urgent Utility Notice',
      question: 'Which message is a fraudulent utility disconnection scam targeting panic?',
      optionA: {
        text: 'Electricity Board Notice: Power will be disconnected tonight at 9:30 PM due to unpaid bill. Call Electricity Officer immediately at 9876543210 to stop disconnection.',
        isScam: true
      },
      optionB: {
        text: 'Dear Consumer, your electricity bill of ₹1,420 for Consumer No. 90421 is generated. Due date is 28-Sep. Pay online via official portal or authorized utility app.',
        isScam: false
      },
      correctOption: 'A',
      explanation: 'Option A is a widespread utility scam. Scammers induce panic with immediate night-time disconnection deadlines and provide personal mobile numbers. When victims call, they are instructed to install remote-access apps (AnyDesk) to steal bank funds.'
    },
    {
      id: 3,
      badge: 'Scenario 3: Work-From-Home Opportunity',
      question: 'Which employment offer is an advance-fee task scam?',
      optionA: {
        text: 'Hello! You are selected for online part-time job. Earn ₹5,000–₹8,000 daily by simply hitting like on YouTube videos. Deposit ₹500 refundable registration fee to activate VIP tasks.',
        isScam: true
      },
      optionB: {
        text: 'Thank you for submitting your application for the Junior Web Developer opening. Please review the formal job description and interview availability on our verified careers portal.',
        isScam: false
      },
      correctOption: 'A',
      explanation: 'Option A is a textbook advance-fee task fraud. Legitimate organizations NEVER ask candidates to pay an upfront "registration fee" or "security deposit" to earn money. The tasks are fake, and deposited money is never returned.'
    },
    {
      id: 4,
      badge: 'Scenario 4: Physical QR Code (Quishing)',
      question: 'Which scenario presents a dangerous physical QR code phishing threat ("Quishing")?',
      optionA: {
        text: 'A digital parking meter screen displaying an official dynamic payment QR code generated per transaction.',
        isScam: false
      },
      optionB: {
        text: 'A paper sticker with a generic QR code pasted directly over the official payment instructions on a public parking meter.',
        isScam: true
      },
      correctOption: 'B',
      explanation: 'Option B represents a physical "Quishing" attack. Attackers paste physical stickers over legitimate public parking meters or restaurant payment counters, silently redirecting victims to cloned payment gateways to steal credit card details.'
    },
    {
      id: 5,
      badge: 'Scenario 5: Bank Phone Call & OTP Verification',
      question: 'Which communication represents a social engineering credential theft attempt?',
      optionA: {
        text: 'A caller claiming to be from Bank Fraud Department says: "An unauthorized ₹25,000 debit was attempted from London. Please share the 6-digit OTP you just received so I can block it."',
        isScam: true
      },
      optionB: {
        text: 'Automated SMS: "₹2,500 debited from A/c XX409 at ATM on 24-Sep. If not done by you, forward this SMS to 567676 or call our official toll-free 1800-425-3800."',
        isScam: false
      },
      correctOption: 'A',
      explanation: 'Option A is an OTP theft attack! Legitimate bank employees will NEVER call and ask you to read out an OTP or PIN. The OTP you received is actually the final verification step required for the attacker to empty your account.'
    }
  ];

  let userAnswers = {}; // { 1: 'B', 2: 'A', ... }

  document.addEventListener('DOMContentLoaded', initAwarenessModule);

  function initAwarenessModule() {
    renderQuiz();

    const resetBtn = document.getElementById('reset-quiz-btn');
    if (resetBtn) {
      resetBtn.addEventListener('click', () => {
        userAnswers = {};
        renderQuiz();
      });
    }
  }

  function renderQuiz() {
    const container = document.getElementById('awareness-scenarios-container');
    if (!container) return;

    container.innerHTML = '';

    SCENARIOS.forEach(item => {
      const card = document.createElement('div');
      card.className = 'scenario-card';
      card.id = `scenario-${item.id}`;

      const answered = userAnswers[item.id];
      const isCorrect = answered === item.correctOption;

      let optAClass = '';
      let optBClass = '';
      if (answered) {
        if (item.correctOption === 'A') {
          optAClass = answered === 'A' ? 'selected-correct' : '';
          optBClass = answered === 'B' ? 'selected-wrong' : '';
        } else {
          optBClass = answered === 'B' ? 'selected-correct' : '';
          optAClass = answered === 'A' ? 'selected-wrong' : '';
        }
      }

      card.innerHTML = `
        <span class="scenario-badge">${item.badge}</span>
        <div class="scenario-question">${item.question}</div>
        <div class="scenario-options">
          <div class="option-box ${optAClass}" data-qid="${item.id}" data-opt="A">
            <div><span class="option-letter">A</span></div>
            <div class="option-content">${escapeHtml(item.optionA.text)}</div>
          </div>
          <div class="option-box ${optBClass}" data-qid="${item.id}" data-opt="B">
            <div><span class="option-letter">B</span></div>
            <div class="option-content">${escapeHtml(item.optionB.text)}</div>
          </div>
        </div>
        <div id="feedback-${item.id}" class="feedback-explanation ${answered ? (isCorrect ? 'correct' : 'wrong') : ''}" style="display: ${answered ? 'block' : 'none'};">
          <strong>${isCorrect ? '✓ Correct Decision!' : '✗ Critical Warning!'}</strong> ${item.explanation}
        </div>
      `;

      container.appendChild(card);
    });

    // Attach click listeners to options
    container.querySelectorAll('.option-box').forEach(box => {
      box.addEventListener('click', (e) => {
        const qid = parseInt(e.currentTarget.getAttribute('data-qid'), 10);
        const selectedOpt = e.currentTarget.getAttribute('data-opt');

        // Allow answering only once per question until reset
        if (userAnswers[qid]) return;

        userAnswers[qid] = selectedOpt;
        renderQuiz();
        updateAwarenessScore();
      });
    });

    updateAwarenessScore();
  }

  function updateAwarenessScore() {
    const totalQuestions = SCENARIOS.length;
    const answeredCount = Object.keys(userAnswers).length;
    let correctCount = 0;

    SCENARIOS.forEach(s => {
      if (userAnswers[s.id] === s.correctOption) {
        correctCount++;
      }
    });

    const scorePercent = answeredCount > 0 ? Math.round((correctCount / totalQuestions) * 100) : 0;

    const scoreDisplay = document.getElementById('awareness-score-val');
    const badgeDisplay = document.getElementById('awareness-rank-badge');
    const summaryText = document.getElementById('awareness-summary-text');

    if (scoreDisplay) scoreDisplay.textContent = `${scorePercent}%`;

    let rankText = 'In Progress';
    let rankBadgeClass = 'badge warning';
    let summary = `Answered ${answeredCount} of ${totalQuestions} scenarios.`;

    if (answeredCount === totalQuestions) {
      if (scorePercent === 100) {
        rankText = '🛡️ Cyber Guardian (Mastery)';
        rankBadgeClass = 'badge safe';
        summary = 'Exceptional threat intuition! You successfully detected 100% of social engineering and phishing vectors.';
      } else if (scorePercent >= 80) {
        rankText = '🔍 Vigilant Defender';
        rankBadgeClass = 'badge safe';
        summary = 'Strong awareness! You caught almost all deceptive patterns.';
      } else if (scorePercent >= 60) {
        rankText = '⚠️ Moderate Awareness';
        rankBadgeClass = 'badge warning';
        summary = 'Caution needed. Review the detailed explanations above to sharpen your detection skills.';
      } else {
        rankText = '🚨 High Vulnerability';
        rankBadgeClass = 'badge critical';
        summary = 'High exposure risk. Practice reviewing domain structures and never share OTPs or click urgent links.';
      }
    }

    if (badgeDisplay) {
      badgeDisplay.textContent = rankText;
      badgeDisplay.className = rankBadgeClass;
    }
    if (summaryText) {
      summaryText.textContent = summary;
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

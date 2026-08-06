// ==========================================================================
// Phishing Threat Analyzer & Security Workbench Logic Engine
// ==========================================================================

// --- Email Dataset ---
const EMAIL_SAMPLES = [
  {
    id: "phish-bank-01",
    type: "phishing",
    riskLevel: "CRITICAL",
    riskScore: 95,
    sender: "Secure Bank Alerts <alert@secure-bank-login-verify.com>",
    displaySender: "Secure Bank Alerts",
    actualEmail: "alert@secure-bank-login-verify.com",
    expectedDomain: "securebank.com",
    subject: "URGENT: Suspicious activity detected on your bank account!",
    date: "August 6, 2026 at 09:14 AM",
    replyTo: "collect-creds@phish-server-x.net",
    spfStatus: "FAIL",
    dkimStatus: "FAIL",
    dmarcStatus: "FAIL",
    body: `Dear Valued Customer,

We detected an unauthorized login attempt to your Secure Bank account from an unrecognized IP address (185.220.101.5) in Moscow, Russia.

For your protection, we have temporarily restricted access to your account. You MUST verify your identity within 24 hours or your account will be PERMANENTLY SUSPENDED and a $150 lock penalty fee will be assessed.

Please click the secure link below to update your security credentials immediately:

[[http://185.168.45.12/securebank-login/verify.html|https://www.securebank.com/account-verify]]

Thank you for your prompt cooperation.

Sincerely,
Secure Bank Fraud Prevention Unit`,
    redFlags: [
      {
        title: "Domain & Sender Address Spoofing",
        severity: "danger",
        icon: "🚨",
        description: "The sender domain 'secure-bank-login-verify.com' is a lookalike fake domain. The real bank domain is 'securebank.com'."
      },
      {
        title: "Suspicious & Mismatched Link Destination",
        severity: "danger",
        icon: "🔗",
        description: "The hyperlink text displays 'https://www.securebank.com', but points to a raw malicious IP address 'http://185.168.45.12/...'."
      },
      {
        title: "Artificial Urgency & Fear Tactics",
        severity: "warning",
        icon: "⏰",
        description: "Uses threats of permanent account suspension within 24 hours and lock penalty fees to cause panic and force rapid action."
      },
      {
        title: "Generic Greeting & Lack of Personalization",
        severity: "info",
        icon: "👤",
        description: "Addressed to 'Dear Valued Customer' instead of your actual name or account identifier."
      },
      {
        title: "Failed Authentication (SPF / DKIM / DMARC)",
        severity: "danger",
        icon: "🛡️",
        description: "Email failed sender verification checks, indicating the email source address was forged."
      }
    ],
    explanation: "This message is a CLASSIC CREDENTIAL HARVESTING PHISHING ATTEMPT. Attackers deploy urgent psychological triggers (account lock panic) combined with link deception (displaying a legitimate bank URL while secretly linking to an attacker-controlled server IP). Entering login credentials on the target page would directly compromise your financial account."
  },
  {
    id: "phish-ceo-02",
    type: "phishing",
    riskLevel: "HIGH",
    riskScore: 88,
    sender: "Robert Sterling (CEO) <robert.sterling.ceo@gmail-exec-portal.net>",
    displaySender: "Robert Sterling (CEO)",
    actualEmail: "robert.sterling.ceo@gmail-exec-portal.net",
    expectedDomain: "acmecorp.com",
    subject: "CONFIDENTIAL: Urgent Wire Transfer Request for M&A Deal",
    date: "August 6, 2026 at 11:42 AM",
    replyTo: "robert-private-acq@consultant.com",
    spfStatus: "PASS",
    dkimStatus: "FAIL",
    dmarcStatus: "FAIL",
    body: `Hi Alex,

I am currently in an urgent confidential meeting regarding an acquisition deal. I need you to initiate a wire transfer of $48,500 immediately to secure the initial legal retainers.

Please transfer the funds to the following escrow account before 2:00 PM today:
Bank: First National Commercial
Routing: 021000021
Account: 88492019482

DO NOT discuss this with anyone in the office or call my phone right now as this transaction is under strict NDA. Send me the wire transfer confirmation receipt as soon as it is executed.

Regards,
Robert Sterling
Chief Executive Officer
Acme Corp`,
    redFlags: [
      {
        title: "Business Email Compromise (BEC) / Executive Impersonation",
        severity: "danger",
        icon: "👔",
        description: "Sender claims to be company CEO, but email originates from 'gmail-exec-portal.net' instead of official corporate domain '@acmecorp.com'."
      },
      {
        title: "Bypassing Internal Financial Controls & Isolation",
        severity: "danger",
        icon: "⛔",
        description: "Instructs recipient NOT to talk to anyone or phone the executive, purposefully cutting off out-of-band verification."
      },
      {
        title: "Extreme Financial Urgency",
        severity: "warning",
        icon: "⚡",
        description: "Demands immediate wire transfer within hours under the guise of an undisclosed confidential acquisition."
      }
    ],
    explanation: "This is a BUSINESS EMAIL COMPROMISE (BEC) / WHALING ATTACK targeting employees with financial authority. Attackers impersonate senior leadership, leverage authority bias, demand secrecy, and attempt to steal corporate funds via wire transfer."
  },
  {
    id: "phish-package-03",
    type: "phishing",
    riskLevel: "HIGH",
    riskScore: 82,
    sender: "Global Courier Express <no-reply@express-delivery-update.xyz>",
    displaySender: "Global Courier Express",
    actualEmail: "no-reply@express-delivery-update.xyz",
    expectedDomain: "globalexpress.com",
    subject: "Action Required: Failed delivery for package #GX-994812",
    date: "August 6, 2026 at 08:05 AM",
    replyTo: "no-reply@express-delivery-update.xyz",
    spfStatus: "PASS",
    dkimStatus: "PASS",
    dmarcStatus: "NONE",
    body: `Hello,

Your package #GX-994812 could not be delivered today because the delivery address provided is incomplete or incorrect.

A redelivery fee of $2.95 must be paid to reschedule shipment. If unaddressed within 48 hours, the parcel will be returned to the origin sender.

Update your delivery details and pay the fee here:
[[http://track-parcel-pay-fee.xyz/reschedule|https://globalexpress.com/track/GX-994812]]

Thank you,
Customer Operations Team`,
    redFlags: [
      {
        title: "Suspicious Top-Level Domain (.xyz)",
        severity: "warning",
        icon: "🌐",
        description: "Uses a cheap, suspicious .xyz domain ('express-delivery-update.xyz') frequently utilized in automated phishing campaigns."
      },
      {
        title: "Link Masking & Deceptive Anchor Text",
        severity: "danger",
        icon: "🔗",
        description: "Displayed text shows 'globalexpress.com', but hovering reveals destination URL is 'track-parcel-pay-fee.xyz'."
      },
      {
        title: "Small Payment Bait (Credit Card Harvesting)",
        severity: "danger",
        icon: "💳",
        description: "Requests a small $2.95 fee to trick victims into entering credit card details on a spoofed payment gateway."
      }
    ],
    explanation: "This is a PARCEL PHISHING (SMISHING/EMAIL) ATTACK designed for Credit Card Harvesting. The low fee ($2.95) lowers victim vigilance, leading them to enter full credit card and personal identity details on a fake portal."
  },
  {
    id: "phish-it-04",
    type: "phishing",
    riskLevel: "MEDIUM-HIGH",
    riskScore: 78,
    sender: "IT Helpdesk <support@company-portal-fix.info>",
    displaySender: "IT Helpdesk",
    actualEmail: "support@company-portal-fix.info",
    expectedDomain: "company.com",
    subject: "Action Required: Microsoft 365 Password Expiration Notice",
    date: "August 6, 2026 at 02:10 PM",
    replyTo: "support@company-portal-fix.info",
    spfStatus: "FAIL",
    dkimStatus: "NONE",
    dmarcStatus: "FAIL",
    body: `Attention Employee,

Your Microsoft 365 corporate password is set to expire in 4 hours. Failure to update your password now will result in account lockout, loss of email access, and disruption of active projects.

Keep your current password by renewing credentials on the IT self-service portal:

[[http://company-portal-fix.info/m365/login|https://portal.office.com/renew-password]]

IT Infrastructure Team`,
    redFlags: [
      {
        title: "External Domain for Supposed Internal IT",
        severity: "danger",
        icon: "🏢",
        description: "Internal IT notifications should originate from your corporate domain, not an external .info address."
      },
      {
        title: "Tight Expiration Pressure",
        severity: "warning",
        icon: "⏱️",
        description: "Imposes a strict 4-hour countdown to prevent victims from verifying with internal IT."
      },
      {
        title: "Credential Harvesting Link",
        severity: "danger",
        icon: "🔑",
        description: "Directs users to a fake Single Sign-On (SSO) login page designed to capture corporate employee login credentials."
      }
    ],
    explanation: "This is an INTERNAL CREDENTIAL HARVESTING PHISHING SCAM targeting corporate logins. Once stolen, attackers use these credentials for initial access into corporate networks (Ransomware/Data exfiltration)."
  },
  {
    id: "legit-security-05",
    type: "legitimate",
    riskLevel: "SAFE",
    riskScore: 5,
    sender: "IT Security Team <security@company.com>",
    displaySender: "IT Security Team",
    actualEmail: "security@company.com",
    expectedDomain: "company.com",
    subject: "Monthly Security Awareness Briefing - August 2026",
    date: "August 6, 2026 at 10:00 AM",
    replyTo: "security@company.com",
    spfStatus: "PASS",
    dkimStatus: "PASS",
    dmarcStatus: "PASS",
    body: `Hello Team,

Welcome to our August Security Awareness Briefing. 

In this month's updates:
1. Overview of recent phishing trends reported by staff.
2. Reminder on multi-factor authentication (MFA) guidelines.
3. Schedule for our upcoming cybersecurity Q&A session.

You can review the full briefing on our internal intranet site:
https://intranet.company.com/security/briefing-august-2026

If you ever receive suspicious emails, please use the 'Report Phishing' button in Outlook or contact security@company.com.

Best regards,
Corporate Information Security Team`,
    redFlags: [],
    explanation: "This message is SAFE and LEGITIMATE. The sender email matches the official corporate domain, SPF/DKIM/DMARC checks all pass, hyperlinks lead exclusively to internal encrypted HTTPS company intranet resources, and no artificial pressure or sensitive requests are present."
  }
];

// --- Security Quiz Questions Dataset ---
const QUIZ_QUESTIONS = [
  {
    id: 1,
    scenario: "You receive an email from 'Amazon Support <service-amazon-orders-help@account-alert-update.com>' claiming an expensive laptop was purchased on your account for $1,899 and instructing you to click a link to cancel the order.",
    options: [
      { text: "Click the link immediately to prevent the charge.", correct: false },
      { text: "Inspect sender address: domain is 'account-alert-update.com', not 'amazon.com'. Report as phishing.", correct: true },
      { text: "Reply to the email asking for a refund.", correct: false },
      { text: "Forward the email to all your friends.", correct: false }
    ],
    explanation: "Correct! The sender address domain 'account-alert-update.com' is a fake lookalike domain. Legitimate notifications from Amazon come from @amazon.com. Never click links in unexpected order confirmation emails; verify order history directly on Amazon's official app/website."
  },
  {
    id: 2,
    scenario: "An email displays a link reading 'https://www.paypal.com/verify-account'. When you hover your cursor over the link, the bottom-left corner of your browser shows 'http://192.241.18.99/paypal/login.php'. What does this indicate?",
    options: [
      { text: "The email is safe because the displayed text says PayPal.", correct: false },
      { text: "The link destination is masked to point to a raw IP address phishing page. It is malicious.", correct: true },
      { text: "It is an internal PayPal IP address for fast loading.", correct: false },
      { text: "It means your browser needs an update.", correct: false }
    ],
    explanation: "Correct! Hyperlink anchor text can display any text (like a legitimate URL), while secretly directing users to a malicious web server (hyperlink masking). Always inspect the actual target URL."
  },
  {
    id: 3,
    scenario: "Your CEO sends an email demanding an urgent $10,000 gift card purchase for a client event, warning you NOT to call them because they are in an all-day conference.",
    options: [
      { text: "Buy the gift cards immediately to impress the CEO.", correct: false },
      { text: "Recognize Executive Impersonation (BEC) and verify out-of-band through standard company channels.", correct: true },
      { text: "Reply with your credit card number.", correct: false },
      { text: "Email the gift card codes directly without asking.", correct: false }
    ],
    explanation: "Correct! Demanding gift cards, urgent transfers, and explicitly instructing victims not to make phone calls are major Business Email Compromise (BEC) red flags."
  },
  {
    id: 4,
    scenario: "What are SPF, DKIM, and DMARC used for in email security?",
    options: [
      { text: "To compress email attachments to make them smaller.", correct: false },
      { text: "To encrypt the body of emails.", correct: false },
      { text: "Authentication protocols that prevent domain spoofing and verify sender identity.", correct: true },
      { text: "To block spam calls on mobile phones.", correct: false }
    ],
    explanation: "Correct! SPF (Sender Policy Framework), DKIM (DomainKeys Identified Mail), and DMARC (Domain-based Message Authentication, Reporting, and Conformance) allow recipient servers to verify whether incoming mail truly originated from the domain listed."
  }
];

// --- State Management ---
let currentEmail = EMAIL_SAMPLES[0];
let quizIndex = 0;
let quizScore = 0;

// --- DOM Content Loaded Initialization ---
document.addEventListener("DOMContentLoaded", () => {
  initTabs();
  renderEmailList();
  selectEmail(EMAIL_SAMPLES[0].id);
  initQuiz();
});

// --- Tab Navigation ---
function initTabs() {
  const navBtns = document.querySelectorAll(".nav-btn");
  const tabContents = document.querySelectorAll(".tab-content");

  navBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      const tabTarget = btn.getAttribute("data-tab");

      navBtns.forEach(b => b.classList.remove("active"));
      tabContents.forEach(c => c.classList.remove("active"));

      btn.classList.add("active");
      document.getElementById(tabTarget).classList.add("active");
    });
  });
}

// --- Email Sidebar Render ---
function renderEmailList() {
  const emailListEl = document.getElementById("emailList");
  if (!emailListEl) return;

  emailListEl.innerHTML = EMAIL_SAMPLES.map(sample => {
    const badgeClass = sample.type === "phishing" 
      ? (sample.riskLevel === "CRITICAL" ? "badge-phishing" : "badge-suspicious") 
      : "badge-legitimate";

    return `
      <div class="email-item ${sample.id === currentEmail.id ? 'active' : ''}" onclick="selectEmail('${sample.id}')">
        <div class="email-item-header">
          <span class="email-sender">${escapeHtml(sample.displaySender)}</span>
          <span class="badge ${badgeClass}">${sample.riskLevel}</span>
        </div>
        <div class="email-subject">${escapeHtml(sample.subject)}</div>
        <div class="email-snippet">${escapeHtml(sample.actualEmail)}</div>
      </div>
    `;
  }).join("");
}

// --- Email Selection & Deep Render ---
function selectEmail(id) {
  const sample = EMAIL_SAMPLES.find(e => e.id === id);
  if (!sample) return;

  currentEmail = sample;
  renderEmailList();

  // Header meta
  document.getElementById("dispSubject").textContent = sample.subject;
  document.getElementById("dispSender").innerHTML = `${escapeHtml(sample.sender)} ${
    sample.actualEmail.includes(sample.expectedDomain) 
      ? "" 
      : `<span class="spoofed-warning">⚠ Domain Mismatch (Expected: @${sample.expectedDomain})</span>`
  }`;
  document.getElementById("dispReplyTo").textContent = sample.replyTo;
  document.getElementById("dispDate").textContent = sample.date;

  // Auth bar
  const spfEl = document.getElementById("authSpf");
  const dkimEl = document.getElementById("authDkim");
  const dmarcEl = document.getElementById("authDmarc");

  if (spfEl) spfEl.className = `auth-tag ${sample.spfStatus === 'PASS' ? 'auth-pass' : 'auth-fail'}`;
  if (spfEl) spfEl.textContent = `SPF: ${sample.spfStatus}`;

  if (dkimEl) dkimEl.className = `auth-tag ${sample.dkimStatus === 'PASS' ? 'auth-pass' : 'auth-fail'}`;
  if (dkimEl) dkimEl.textContent = `DKIM: ${sample.dkimStatus}`;

  if (dmarcEl) dmarcEl.className = `auth-tag ${sample.dmarcStatus === 'PASS' ? 'auth-pass' : 'auth-fail'}`;
  if (dmarcEl) dmarcEl.textContent = `DMARC: ${sample.dmarcStatus}`;

  // Body content with parsing highlights
  const bodyEl = document.getElementById("dispBody");
  if (bodyEl) {
    bodyEl.innerHTML = parseEmailBodyHighlights(sample.body);
  }

  // Risk Dashboard
  const scoreValEl = document.getElementById("riskScoreVal");
  const meterEl = document.getElementById("riskMeter");
  const verdictEl = document.getElementById("riskVerdict");

  if (scoreValEl) scoreValEl.textContent = `${sample.riskScore}%`;
  if (meterEl) meterEl.style.setProperty("--score", sample.riskScore);

  if (verdictEl) {
    verdictEl.textContent = `${sample.riskLevel} PHISHING RISK`;
    verdictEl.style.color = sample.type === "phishing" ? "var(--accent-red)" : "var(--accent-emerald)";
  }

  // Red Flags Grid
  const redFlagsGrid = document.getElementById("redFlagsGrid");
  if (redFlagsGrid) {
    if (sample.redFlags.length === 0) {
      redFlagsGrid.innerHTML = `
        <div class="flag-card safe">
          <div class="flag-icon">✅</div>
          <div class="flag-content">
            <h4>No Phishing Red Flags Detected</h4>
            <p>Email satisfies security authentication standards and originates from an authorized server.</p>
          </div>
        </div>
      `;
    } else {
      redFlagsGrid.innerHTML = sample.redFlags.map(flag => `
        <div class="flag-card ${flag.severity}">
          <div class="flag-icon">${flag.icon}</div>
          <div class="flag-content">
            <h4>${escapeHtml(flag.title)}</h4>
            <p>${escapeHtml(flag.description)}</p>
          </div>
        </div>
      `).join("");
    }
  }

  // Safety explanation
  const expEl = document.getElementById("dispExplanation");
  if (expEl) expEl.textContent = sample.explanation;
}

// --- Body Highlight Parser ---
function parseEmailBodyHighlights(rawText) {
  let formatted = escapeHtml(rawText);

  // Link format: [[destinationURL|displayText]]
  const linkRegex = /\[\[(.*?)\|(.*?)\]\]/g;
  formatted = formatted.replace(linkRegex, (match, dest, text) => {
    return `<span class="hl-link" data-dest="Actual target: ${escapeHtml(dest)}">${escapeHtml(text)}</span>`;
  });

  // Urgent Keywords
  const keywords = ["URGENT", "PERMANENTLY SUSPENDED", "24 hours", "4 hours", "lock penalty fee", "verify your identity", "immediate wire transfer", "DO NOT discuss", "redelivery fee", "renew credentials"];
  keywords.forEach(kw => {
    const re = new RegExp(`(${escapeRegExp(kw)})`, 'gi');
    formatted = formatted.replace(re, `<span class="hl-keyword" title="Urgent / Suspicious Keyword">$1</span>`);
  });

  return formatted;
}



// --- Interactive Quiz Logic ---
function initQuiz() {
  quizIndex = 0;
  quizScore = 0;
  renderQuizQuestion();
}

function renderQuizQuestion() {
  const q = QUIZ_QUESTIONS[quizIndex];
  if (!q) {
    renderQuizFinalScore();
    return;
  }

  const fill = document.getElementById("quizProgressFill");
  if (fill) fill.style.width = `${((quizIndex + 1) / QUIZ_QUESTIONS.length) * 100}%`;

  const container = document.getElementById("quizCard");
  if (!container) return;

  container.innerHTML = `
    <div class="quiz-email-preview">
      <strong>Scenario ${q.id} of ${QUIZ_QUESTIONS.length}:</strong><br>
      <p style="margin-top:0.5rem; color: #e2e8f0;">${escapeHtml(q.scenario)}</p>
    </div>

    <div class="quiz-options">
      ${q.options.map((opt, i) => `
        <button class="quiz-option-btn" onclick="submitQuizAnswer(${i})">
          ${escapeHtml(opt.text)}
        </button>
      `).join("")}
    </div>
    <div id="quizFeedback" class="quiz-feedback"></div>
  `;
}

function submitQuizAnswer(chosenIdx) {
  const q = QUIZ_QUESTIONS[quizIndex];
  const option = q.options[chosenIdx];
  const feedbackEl = document.getElementById("quizFeedback");

  if (option.correct) {
    quizScore++;
    feedbackEl.className = "quiz-feedback correct";
    feedbackEl.innerHTML = `<strong>✅ Correct!</strong> ${q.explanation}`;
  } else {
    feedbackEl.className = "quiz-feedback incorrect";
    feedbackEl.innerHTML = `<strong>❌ Incorrect.</strong> ${q.explanation}`;
  }

  // Disable buttons
  const btns = document.querySelectorAll(".quiz-option-btn");
  btns.forEach(b => b.style.pointerEvents = "none");

  setTimeout(() => {
    quizIndex++;
    if (quizIndex < QUIZ_QUESTIONS.length) {
      renderQuizQuestion();
    } else {
      renderQuizFinalScore();
    }
  }, 3500);
}

function renderQuizFinalScore() {
  const container = document.getElementById("quizCard");
  if (!container) return;

  const percentage = Math.round((quizScore / QUIZ_QUESTIONS.length) * 100);

  container.innerHTML = `
    <div style="text-align: center; padding: 2rem;">
      <h2 style="font-size: 1.8rem; margin-bottom: 1rem;">Quiz Complete!</h2>
      <div style="font-size: 3rem; font-weight: 800; color: var(--accent-cyan); font-family: var(--font-mono); margin-bottom: 0.5rem;">
        ${quizScore} / ${QUIZ_QUESTIONS.length} (${percentage}%)
      </div>
      <p style="color: var(--text-secondary); margin-bottom: 1.5rem;">
        ${percentage >= 75 ? "🎉 Excellent threat detection skills! You are well-prepared to spot phishing attacks." : "⚠️ Keep practicing! Review the Red Flag Matrix to strengthen your security awareness."}
      </p>
      <button class="btn-primary" style="margin: 0 auto;" onclick="initQuiz()">Restart Quiz</button>
    </div>
  `;
}

// --- Utilities ---
function escapeHtml(str) {
  if (!str) return '';
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function escapeRegExp(string) {
  return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

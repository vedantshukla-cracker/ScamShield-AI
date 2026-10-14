# 🛡️ ScamShield AI

> **Pause before you trust. Stay alert, stay protected.**

ScamShield AI is a modern, client-side digital scam and phishing threat detection engine built with HTML5, Vanilla CSS, and JavaScript. It empowers users to analyze suspicious messages, phishing links, caller IDs, fake prize schemes, and coercive threats before falling victim to cyber fraud.

---

## 🚀 Features

- **Multi-Vector Threat Scanner:** Analyze suspicious SMS, WhatsApp chats, emails, Telegram DMs, and job offers.
- **Phishing Link & Domain Deep Inspector:** Detects brand impersonation, suspicious TLDs (`.xyz`, `.top`, `.cam`, `.buzz`), raw IP destinations, and insecure HTTP protocols.
- **Caller & Sender Header Check:** Flags high-risk international prefixes, virtual VoIP cues, and telecom SMS header formats.
- **Dynamic Risk Gauge (0–100):** Visual threat score breakdown across *Clean*, *Low Risk*, *Moderate Caution*, and *Critical Scam Hazard*.
- **Interactive High-Risk Phrase Highlighter:** Highlights manipulative phrasing and attack keywords with contextual warning tooltips.
- **Attacker Playbook & Modus Operandi:** Unmasks the psychological coercion, advance-fee trap, or credential harvesting strategy being deployed.
- **Recommended Safety Protocol:** Actionable, step-by-step containment checklist to protect accounts, cards, and personal data.
- **One-Click Shareable Threat Report:** Easily copy a formatted risk breakdown to share with family and friends.
- **Instant Preset Scenarios:** 6 realistic one-click scenarios (Bank KYC Alert, Failed Delivery Smishing, 2x Crypto Doubler, Work From Home Scam, Digital Arrest Threat, and Legit Order Confirmation).
- **Interactive Scam Instinct Trainer (Quiz):** Practice distinguishing real company communications from sophisticated fraud via a phone mockup simulator.
- **Emergency Crisis Response Center:** Immediate 2-hour window recovery steps and national cybercrime helpline directory (India 1930, US IC3/FTC, UK Action Fraud, Global APWG).
- **Persistent Local History:** View, reload, and review past scans saved privately in browser `localStorage`.
- **Zero-Dependency Web Audio API:** High-tech synthetic UI sound effects with a persistent toggleable mute switch.
- **Responsive & Modern UI:** Glassmorphism cyber-defense theme with fluid typography, dark mode aesthetics, and full mobile responsiveness.

---

## 🛠️ Tech Stack

- **HTML5:** Semantic architecture, accessible forms, tabs, and ARIA labels.
- **CSS3:** Custom properties (variables), backdrop-filter glassmorphism, flexbox, CSS grid, and SVG keyframe animations.
- **JavaScript (ES6+):** Pure vanilla JavaScript client-side heuristic engine, Web Audio API synthesis, and `localStorage` state management.

---

## 📁 Project Structure

```text
ScamShield-AI/
├── index.html         # Main application markup & UI layout
├── style.css          # Glassmorphism cyber-shield design system
├── script.js          # Heuristic engine, URL inspector, quiz & audio
├── shield-logo.jpg    # Holographic 3D cyber shield branding emblem
└── README.md          # Project documentation
```

---

## 💻 How to Run Locally

1. **Clone or Download the Repository:**
   ```bash
   git clone https://github.com/your-username/ScamShield-AI.git
   ```

2. **Navigate to the Project Folder:**
   ```bash
   cd ScamShield-AI
   ```

3. **Launch the Application:**
   - Double-click `index.html` to open it in your default web browser, **or**
   - Use the **Live Server** extension in Visual Studio Code / Antigravity IDE.

*No Node.js, external libraries, or build steps required!*

---

## 🔍 How It Works

1. **Select an Input Mode:** Choose between **Message / SMS**, **Link Inspector**, or **Caller Check** tabs.
2. **Input Content:** Paste suspicious text or choose one of the one-click realistic scam presets.
3. **Execute Scan:** Click **Analyze Content** to trigger the sub-second heuristic scan.
4. **Evaluate Threat Level:** Review the circular risk gauge, highlighted danger phrases, and detected red flags.
5. **Take Action:** Follow the tailored safety protocols, copy the report, or consult the Emergency Directory.

---

## 🔐 Privacy and Security

- **100% Client-Side:** All text analysis, URL parsing, and scoring run entirely within your local browser runtime.
- **Zero Data Logging:** No messages, URLs, phone numbers, or telemetry are ever uploaded or transmitted to any external server.
- **Local Cache Only:** Scan history is stored strictly in your browser's private `localStorage`.

> **Disclaimer:** ScamShield AI is an educational heuristic tool designed to promote digital literacy and cyber safety. While it detects dozens of common scam patterns, no automated tool can guarantee absolute safety. Always independently verify suspicious communications through official, trusted channels. Never share passwords, OTPs, PINs, or financial credentials.

---

## 🎯 Roadmap & Future Improvements

- [x] Client-side heuristic rule engine with compound risk weighting.
- [x] Advanced URL phishing and typosquatting inspector.
- [x] Interactive Scam Instinct Quiz & Training Simulator.
- [x] Emergency hotline directory and crisis protocol.
- [ ] Integration with open-source client-side WebLLM / Transformers.js models.
- [ ] Multilingual scam detection (Hindi, Spanish, French, etc.).
- [ ] Browser extension for real-time link and email scanning.
- [ ] Export assessment report as PDF / Image badge.

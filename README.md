<h1 align="center">
  <a><img src="https://github.com/nivlevyy/UBE-Ublock_Enhance/blob/main/image/UBE-logo.jpeg" width="300"></a>
<br>
AI-Powered Phishing Detection Extension
<br>
</h1>

## Overview

This project is an AI-powered phishing detection system integrated directly into the **uBlock Origin** browser extension. It enhances traditional ad-blockers by enabling real-time detection of phishing threats using machine learning. The extension analyzes various website elements including URLs, domain metadata, HTML structure, and JavaScript behavior to identify suspicious activity.

Unlike static blacklists, our approach adapts dynamically to evolving phishing tactics and provides high accuracy with low latency, all while preserving user privacy by running entirely on the client side using **TensorFlow.js**.

---

## Core Features

### AI-Powered Detection Pipeline
- **Stage 1**: URL lexical feature analysis (length, use of IP, special characters).
- **Stage 2**: Domain reputation and WHOIS-based features.
- **Stage 3**: HTML and JavaScript structural and behavioral analysis.
- **Stage 4** (optional): Visual/NLP-based semantic analysis for future integration.

### Browser Integration
- Built as an extension for **Google Chrome** and **Mozilla Firefox**.
- Hooks into browser events to inspect webpages in real time.
- Enhances uBlock Origin's static list with dynamic, intelligent detection.

### Privacy and Performance
- All detection is performed locally using **TensorFlow.js**.
- No sensitive data is sent to external servers.
- Optional cloud-based backend for list/model updates (NAS).

---

## Technologies Used
- **Languages**: JavaScript, Python
- **Machine Learning**: TensorFlow.js, Scikit-learn, River
- **Frontend**: HTML, CSS, JS (WebExtension APIs)
- **Backend (Optional)**: NAS server for blacklist/model update management
- **Tools**: BeautifulSoup, Whois, Regex, uBlock Origin

---

## Installation & Usage
_**Coming Soon:**_ Instructions for installing the extension, training the model, and updating threat lists will be added here as development progresses.

---

## File Structure
_**To be updated.**_ Will include:
- Python feature extraction scripts
- TensorFlow.js model files
- Browser extension logic and manifest
- NAS server scripts for backend sync

---

## Future Enhancements
- Visual/NLP phishing detection (Stage 4)
- Advanced whitelist/blacklist learning
- User feedback mechanism for training data
- Dashboard for managing blocked threats

---

## License
This project will be licensed under the MIT License.

---

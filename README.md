# AEGIS // Secure Forensic Evidence Locker Web Application
### Cyber Forensics Laboratory Project

A modern, tamper-evident 5-page web application simulating digital forensics evidence ingestion, cryptographic integrity verification, immutable chain of custody audit logging, Role-Based Access Control (RBAC), input sanitization, and Time-Based One-Time Password (TOTP) 2FA.

---

## 5 Security Features & Their Web Pages

| Page | File Name | Security Control | Cyber Forensics Functionality |
| :--- | :--- | :--- | :--- |
| **Gate** | [`login.html`](login.html) | **3. Role selection** | Pick a role (Lead Investigator, Forensic Analyst, Compliance Auditor) and see the permission matrix before entering. |
| **Page 1** | [`index.html`](index.html) | **1. Cryptographic File Hashing** | SHA-256 calculation on evidence upload using the browser's native Web Crypto API. Stores baseline hash records. |
| **Page 2** | [`integrity-verifier.html`](integrity-verifier.html) | **1b. Live Integrity & Tamper Lab** | Compares stored baseline hashes against current ones. Simulates tampering to demonstrate the avalanche effect. |
| **Page 3** | [`chain-of-custody.html`](chain-of-custody.html) | **2. Audit Logging (Chain of Custody)** | Chronological timeline of every interaction, including denied attempts. CSV download and print certificate. |
| **Page 4** | [`rbac-console.html`](rbac-console.html) | **3. Role-Based Access Control (RBAC)** | Switch role and test each action; denied attempts are blocked and written to the audit log. Shows the full permission matrix (Principle of Least Privilege). |
| **Page 5** | [`security-gateway.html`](security-gateway.html) | **4 & 5. File Sanitization & TOTP 2FA** | Filename path traversal (`../`) neutraliser and a 30-second rolling TOTP-style token demo. |

---

## How to Launch the Web Application

### Direct Browser Launch:
Open [`login.html`](login.html) first, choose a role, then use the navigation bar.

All pages share data through `localStorage` (evidence, audit log) and `sessionStorage` (current role), and include a header navigation bar. There is no backend: everything runs in the browser.

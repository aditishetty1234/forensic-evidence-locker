# AEGIS // Secure Forensic Evidence Locker Web Application
### Cyber Forensics Laboratory Project

A modern, tamper-evident 5-page web application simulating digital forensics evidence ingestion, cryptographic integrity verification, immutable chain of custody audit logging, Role-Based Access Control (RBAC), input sanitization, and Time-Based One-Time Password (TOTP) 2FA.

---

## 5 Security Features & Their 5 Dedicated Web Pages

| Page | File Name | Security Control | Cyber Forensics Functionality |
| :--- | :--- | :--- | :--- |
| **Page 1** | [`index.html`](index.html) | **1. Cryptographic File Hashing** | Real-time SHA-256 calculation upon evidence upload using the browser's native Web Crypto API. Stores baseline hash records. |
| **Page 2** | [`integrity-verifier.html`](integrity-verifier.html) | **1b. Live Integrity & Tamper Lab** | Compares stored baseline hashes against active files. Simulates 1-byte file tampering to demonstrate the cryptographic avalanche effect. |
| **Page 3** | [`chain-of-custody.html`](chain-of-custody.html) | **2. Immutable Audit Logging** | Append-only chronological timeline of every interaction. Proves legal chain of custody for court admissibility. Includes CSV download and print certificate. |
| **Page 4** | [`rbac-console.html`](rbac-console.html) | **3. Role-Based Access Control (RBAC)** | Dynamic permission gating between Lead Investigator, Forensic Analyst, and Compliance Auditor enforcing the Principle of Least Privilege. |
| **Page 5** | [`security-gateway.html`](security-gateway.html) | **4 & 5. File Sanitization & TOTP 2FA** | Live filename path traversal neutralizer (`../`) and 30-second rolling RFC 6238 TOTP authenticator token verification. |

---

## How to Launch the Web Application

### Direct Browser Launch:
Open any of the pages directly in your browser:
* [`index.html`](index.html) (Page 1)
* [`integrity-verifier.html`](integrity-verifier.html) (Page 2)
* [`chain-of-custody.html`](chain-of-custody.html) (Page 3)
* [`rbac-console.html`](rbac-console.html) (Page 4)
* [`security-gateway.html`](security-gateway.html) (Page 5)

All 5 pages share synchronized live data using `localStorage` and include cohesive top header and bottom footer navigation bars.

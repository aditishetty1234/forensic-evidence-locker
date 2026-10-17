# AEGIS // Secure Forensic Evidence Locker Web Application
### Cyber Forensics Laboratory Project

A modern, tamper-evident web portal simulating digital forensics evidence ingestion, cryptographic integrity verification, immutable chain of custody audit logging, Role-Based Access Control (RBAC), and Time-Based One-Time Password (TOTP) 2FA.

---

## 5 Security Features Implemented

| Security Feature | Cyber Forensics Utility | How It Is Implemented in this Project |
| :--- | :--- | :--- |
| **1. Cryptographic File Hashing (SHA-256)** | Guarantees evidence integrity and legal chain of custody. | Automatically computes SHA-256 digests in real-time via the native Web Crypto API (`crypto.subtle.digest`) upon file upload. Includes a live re-verification workbench and side-by-side hash comparison sandbox. |
| **2. Immutable Audit Logging (Chain of Custody)** | Preserves an untampered historical record required for court admissibility (FRE Rule 901/902). | An append-only ledger recording timestamp, investigator name, role, IP address, action type, target item, and SHA-256 snapshot. Includes CSV export and printable court certificate generation. |
| **3. Role-Based Access Control (RBAC)** | Enforces the Principle of Least Privilege (PoLP). | Role switcher supporting **Lead Investigator** (full ingestion, tamper simulation, transfer), **Forensic Analyst** (hash verification, read-only analysis), and **Compliance Auditor** (custody logs & compliance review). |
| **4. Input Validation & File Sanitization** | Prevents Remote Code Execution (RCE) and Arbitrary File Upload attacks. | Real-time input sanitizer that strips directory traversal characters (`../`), null bytes, and script injection tags (`<script>`), enforcing secure naming conventions for isolated storage. |
| **5. Time-Based One-Time Password (TOTP) 2FA** | Prevents unauthorized access and credential theft. | RFC 6238 30-second rolling token generator with real-time countdown, secret key seed, QR code representation, and token entry keypad. |

---

## Features & Pages Included

1. **Evidence Vault & Ingestion**:
   - Drag-and-drop file upload zone with live SHA-256 generation.
   - Interactive Input Sanitization & Threat Shield test bench.
   - Evidence inventory with tags, classifications, baseline hashes, and quick actions.

2. **Live Integrity & Tamper Lab**:
   - Side-by-side hash comparison between Database Baseline Hash and Live Computed Disk Hash.
   - "Simulate 1-Byte Tampering" button to demonstrate the cryptographic avalanche effect.
   - Bitstream Hex viewer showing exact modified bytes.
   - One-click baseline restoration.

3. **Tamper-Evident Chain of Custody Ledger**:
   - Chronological event timeline of all operations.
   - Filter by officer, action, or IP address.
   - One-click CSV and court certificate export.

4. **RBAC & 2FA Console**:
   - Live role switcher and permission matrix.
   - 30-second rolling TOTP token authenticator.

5. **Lab Report & Backend Starters**:
   - Complete academic Cyber Forensics Lab Report template.
   - Production-ready **Node.js / Express** backend implementation (`server.js`).
   - Production-ready **Python / Flask** backend implementation (`app.py`).

---

## How to Launch the Web Application

### Method 1: Direct Browser Launch (Recommended)
Simply open the `index.html` file in any modern web browser:
```
C:\Users\Admin\.gemini\antigravity-ide\scratch\forensic-evidence-locker\index.html
```

### Method 2: Local HTTP Server (Python)
Run the following command in PowerShell:
```powershell
cd C:\Users\Admin\.gemini\antigravity-ide\scratch\forensic-evidence-locker
python -m http.server 8080
```
Then navigate to: `http://localhost:8080` in your web browser.

### Method 3: Local HTTP Server (Node.js)
```powershell
cd C:\Users\Admin\.gemini\antigravity-ide\scratch\forensic-evidence-locker
npx serve .
```

---

## Project Structure
```
forensic-evidence-locker/
│
├── index.html        # Modern HTML5 responsive user interface
├── styles.css        # Cyber forensics dark tech theme design system
├── app.js            # Web Crypto SHA-256 engine, RBAC, TOTP, and ledger logic
└── README.md         # Documentation and project instructions
```

/**
 * FORENSIC EVIDENCE LOCKER - APPLICATION LOGIC
 * Shared between all web pages:
 * Gate:   login.html (Feature #3: Least-Privilege Gate - role selection at the very start)
 * Page 1: index.html (Evidence Vault)
 * Page 2: integrity-verifier.html (Integrity Lab)
 * Page 3: chain-of-custody.html (Audit Ledger)
 * Page 4: rbac-console.html (Access Control simulator)
 * Page 5: security-gateway.html (2FA & Sanitization)
 */

// ----------------------------------------------------------------------------
// 0. FEATURE #3: LEAST-PRIVILEGE GATE (ROLE-BASED ACCESS CONTROL)
//    The user picks a role on login.html. That role is stored for the browser
//    tab (sessionStorage) and every page + every sensitive action checks it.
// ----------------------------------------------------------------------------

const SESSION_KEY = 'forensic_session';

// Every page of the app. "file" is the HTML file name used for links.
const PAGES = {
  vault:    { file: 'index.html',              label: 'Evidence Vault' },
  verifier: { file: 'integrity-verifier.html', label: 'Integrity Verifier' },
  custody:  { file: 'chain-of-custody.html',   label: 'Chain of Custody' },
  rbac:     { file: 'rbac-console.html',       label: 'Access Control' },
  security: { file: 'security-gateway.html',   label: '2FA & Sanitization' }
};

// What each role is, which pages it may open, and where it lands after login.
const ROLE_CONFIG = {
  'Lead Investigator': {
    tagline: 'Full Access',
    summary: 'Owns the case. Can ingest, verify, test tamper detection, export certificates and transfer custody.',
    landing: 'index.html',
    pages: ['vault', 'verifier', 'custody', 'rbac', 'security'],
    pageDenyReason: {}
  },
  'Forensic Analyst': {
    tagline: 'Verify & Inspect Only',
    summary: 'Examines evidence and verifies hashes. Cannot add, alter or hand over evidence.',
    landing: 'index.html',
    pages: ['vault', 'verifier', 'custody', 'rbac', 'security'],
    pageDenyReason: {}
  },
  'Compliance Auditor': {
    tagline: 'Read-Only Logs',
    summary: 'Independent reviewer. Works with the audit trail only, never with live evidence files.',
    landing: 'chain-of-custody.html',
    pages: ['custody', 'rbac', 'security'],
    pageDenyReason: {
      vault: 'Auditors inspect custody logs, not active evidence files.',
      verifier: 'Auditors inspect custody logs, not active evidence files.'
    }
  }
};

// Permission matrix: one source of truth for the login page, page locks and action checks.
const PERMISSION_MATRIX = {
  UPLOAD_EVIDENCE: {
    label: 'Ingest New Evidence & Hash',
    roles: {
      'Lead Investigator': { allow: true, reason: 'Lead Investigators hold full evidentiary ingestion rights.' },
      'Forensic Analyst': { allow: false, reason: 'Forensic Analysts have read/verify rights only (Least Privilege Policy).' },
      'Compliance Auditor': { allow: false, reason: 'Auditors are restricted from creating or modifying evidence.' }
    }
  },
  VERIFY_INTEGRITY: {
    label: 'Recalculate & Verify Integrity',
    roles: {
      'Lead Investigator': { allow: true, reason: 'Lead Investigators can run cryptographic verifications.' },
      'Forensic Analyst': { allow: true, reason: 'Forensic Analysts are authorized to compute & verify hashes.' },
      'Compliance Auditor': { allow: false, reason: 'Auditors inspect custody logs, not active evidence files.' }
    }
  },
  SIMULATE_TAMPER: {
    label: 'Simulate / Restore File Alteration',
    roles: {
      'Lead Investigator': { allow: true, reason: 'Authorized for security research and vulnerability demonstration.' },
      'Forensic Analyst': { allow: false, reason: 'Analysts cannot execute file alteration routines.' },
      'Compliance Auditor': { allow: false, reason: 'Strictly prohibited from tampering with evidence.' }
    }
  },
  VIEW_LOGS: {
    label: 'Inspect Chain of Custody Logs',
    roles: {
      'Lead Investigator': { allow: true, reason: 'Access granted to audit trail.' },
      'Forensic Analyst': { allow: true, reason: 'Access granted to audit trail.' },
      'Compliance Auditor': { allow: true, reason: 'Primary responsibility: independent compliance review.' }
    }
  },
  EXPORT_CERT: {
    label: 'Export Court Certificate / Log',
    roles: {
      'Lead Investigator': { allow: true, reason: 'Authorized to issue court certificates.' },
      'Forensic Analyst': { allow: false, reason: 'Analysts cannot issue legal certificates or export the ledger.' },
      'Compliance Auditor': { allow: true, reason: 'Auditors may export the ledger for compliance review.' }
    }
  },
  TRANSFER_CUSTODY: {
    label: 'Transfer Evidence Custody (Requires 2FA)',
    roles: {
      'Lead Investigator': { allow: true, reason: 'Permitted upon secondary TOTP 2FA approval.' },
      'Forensic Analyst': { allow: false, reason: 'Cannot transfer legal custody between agencies.' },
      'Compliance Auditor': { allow: false, reason: 'Cannot transfer custody.' }
    }
  }
};

// --- session helpers --------------------------------------------------------

function getSession() {
  try {
    const raw = sessionStorage.getItem(SESSION_KEY);
    if (!raw) return null;
    const s = JSON.parse(raw);
    // Reject a session whose role is not one we know about (tampered storage).
    if (!s || !ROLE_CONFIG[s.role]) return null;
    return s;
  } catch (e) {
    return null;
  }
}

function setSession(session) {
  sessionStorage.setItem(SESSION_KEY, JSON.stringify(session));
}

function clearSession() {
  try { sessionStorage.removeItem(SESSION_KEY); } catch (e) { /* ignore */ }
}

function currentRole() {
  const s = getSession();
  return s ? s.role : null;
}

// Name stored in the audit log for every action: "Name (Role)".
function currentActor() {
  const s = getSession();
  return s ? `${s.name} (${s.role})` : 'Unauthenticated User';
}

function currentUserName() {
  const s = getSession();
  return s ? s.name : '';
}

function esc(value) {
  return String(value).replace(/[&<>"']/g, c => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

// --- permission checks ------------------------------------------------------

function can(permKey) {
  const role = currentRole();
  const entry = PERMISSION_MATRIX[permKey];
  if (!role || !entry) return false;
  return !!entry.roles[role].allow;
}

function permReason(permKey) {
  const role = currentRole();
  const entry = PERMISSION_MATRIX[permKey];
  return (role && entry) ? entry.roles[role].reason : 'No active session.';
}

function canOpenPage(role, pageKey) {
  return !!ROLE_CONFIG[role] && ROLE_CONFIG[role].pages.includes(pageKey);
}

// Called at the start of every sensitive action. Blocks + audit-logs a denial.
function requirePerm(permKey) {
  if (can(permKey)) return true;
  const label = PERMISSION_MATRIX[permKey] ? PERMISSION_MATRIX[permKey].label : permKey;
  appendCustodyLog(currentActor(), 'Access Denied', `Action: ${label}`, 'Access Denied');
  showToast(`ACCESS DENIED: ${permReason(permKey)}`);
  return false;
}

// --- page guard -------------------------------------------------------------

// Every page calls this first. Returns true when the page may run.
function guardPage(pageKey) {
  const session = getSession();
  if (!session) {
    window.location.replace('login.html');
    return false;
  }

  renderSessionBar(session);
  lockRestrictedLinks(session.role);

  if (!canOpenPage(session.role, pageKey)) {
    showAccessDenied(session, pageKey);
    return false;
  }
  return true;
}

function showAccessDenied(session, pageKey) {
  const cfg = ROLE_CONFIG[session.role];
  const reason = cfg.pageDenyReason[pageKey] || 'This page is outside your role.';
  const pageLabel = PAGES[pageKey] ? PAGES[pageKey].label : 'This page';

  appendCustodyLog(currentActor(), 'Access Denied', `Page: ${pageLabel}`, 'Access Denied');

  const main = document.querySelector('main.page-container');
  if (!main) return;
  main.innerHTML = `
    <section class="card ac-denied">
      <div class="ac-denied-icon">&#128274;</div>
      <h1>Access Denied</h1>
      <p><strong>${esc(pageLabel)}</strong> is not available to the
        <strong>${esc(session.role)}</strong> role.</p>
      <p class="ac-denied-reason">${esc(reason)}</p>
      <div class="ac-denied-actions">
        <a class="btn btn-primary" href="${cfg.landing}">Go to my allowed area</a>
        <a class="btn btn-secondary" href="login.html">Switch role</a>
      </div>
    </section>
  `;
}

// Adds the "signed in as" bar directly under the site header.
function renderSessionBar(session) {
  const header = document.querySelector('.site-header');
  if (!header || document.getElementById('sessionBar')) return;

  const cfg = ROLE_CONFIG[session.role];
  const allowedOps = Object.keys(PERMISSION_MATRIX).filter(k => PERMISSION_MATRIX[k].roles[session.role].allow).length;
  const totalOps = Object.keys(PERMISSION_MATRIX).length;

  const bar = document.createElement('div');
  bar.id = 'sessionBar';
  bar.className = 'ac-session-bar';
  bar.innerHTML = `
    <div class="ac-session-inner">
      <div class="ac-session-who">
        Signed in as <strong>${esc(session.name)}</strong>
        <span class="ac-role-pill">${esc(session.role)}</span>
        <span class="ac-session-meta">${esc(cfg.tagline)} &middot; ${allowedOps}/${totalOps} operations &middot; ${cfg.pages.length}/${Object.keys(PAGES).length} pages</span>
      </div>
      <div class="ac-session-actions">
        <a class="btn btn-secondary btn-sm" href="login.html">Switch Role</a>
        <button type="button" class="btn btn-secondary btn-sm" onclick="signOut()">Sign Out</button>
      </div>
    </div>
  `;
  header.insertAdjacentElement('afterend', bar);
}

// Any link to a page the role cannot open is shown locked and will not navigate.
function lockRestrictedLinks(role) {
  const fileToKey = {};
  Object.keys(PAGES).forEach(k => { fileToKey[PAGES[k].file] = k; });

  document.querySelectorAll('a[href]').forEach(a => {
    const file = (a.getAttribute('href') || '').split('/').pop();
    const key = fileToKey[file];
    if (!key || canOpenPage(role, key)) return;

    a.classList.add('ac-locked');
    a.setAttribute('aria-disabled', 'true');
    a.title = `Locked for ${role}`;
    a.addEventListener('click', (e) => {
      e.preventDefault();
      showToast(`ACCESS DENIED: ${PAGES[key].label} is not available to the ${role} role.`);
    });
  });
}

// Elements marked data-perm="PERMISSION_KEY" are disabled when the role lacks it.
function applyPermissionLocks() {
  document.querySelectorAll('[data-perm]').forEach(el => {
    const perm = el.dataset.perm;
    if (can(perm)) return;

    el.classList.add('ac-perm-locked');
    const isContainer = ['SECTION', 'DIV', 'FORM'].includes(el.tagName);
    if (!isContainer) el.title = `Locked: ${permReason(perm)}`;

    if ('disabled' in el) el.disabled = true;
    el.querySelectorAll('input, select, textarea, button').forEach(c => { c.disabled = true; });

    if (isContainer && !el.querySelector(':scope > .ac-lock-note')) {
      el.insertAdjacentHTML('afterbegin',
        `<div class="ac-lock-note">&#128274; Locked for <strong>${esc(currentRole())}</strong>: ${esc(permReason(perm))}</div>`);
    }
  });
}

function signOut() {
  appendCustodyLog(currentActor(), 'Sign Out', 'Session Gate', 'Session Closed');
  clearSession();
  window.location.href = 'login.html';
}

// ----------------------------------------------------------------------------
// 0b. LOGIN PAGE (login.html)
// ----------------------------------------------------------------------------

let loginSelectedRole = null;

function initLoginPage() {
  const existing = getSession();
  if (existing) {
    loginSelectedRole = existing.role;
    document.getElementById('loginName').value = existing.name;
    const note = document.getElementById('loginExisting');
    if (note) {
      note.style.display = 'block';
      note.innerHTML = `Currently signed in as <strong>${esc(existing.name)}</strong> (${esc(existing.role)}). Pick a role to switch.`;
    }
  }

  renderRoleCards();
  renderPermissionMatrix();
  updateLoginSummary();
}

function renderRoleCards() {
  const wrap = document.getElementById('roleCards');
  if (!wrap) return;

  wrap.innerHTML = Object.keys(ROLE_CONFIG).map(role => {
    const selected = loginSelectedRole === role;
    return `<button type="button" class="ac-role-choice ${selected ? 'selected' : ''}" data-role="${esc(role)}" aria-pressed="${selected}">${esc(role)}</button>`;
  }).join('');

  wrap.querySelectorAll('.ac-role-choice').forEach(btn => {
    btn.addEventListener('click', () => selectLoginRole(btn.dataset.role));
  });
}

function selectLoginRole(role) {
  loginSelectedRole = role;
  renderRoleCards();
  renderPermissionMatrix();
  updateLoginSummary();
}

function updateLoginSummary() {
  const btn = document.getElementById('loginSubmit');
  const summary = document.getElementById('loginSummary');
  if (!btn || !summary) return;

  if (!loginSelectedRole) {
    btn.disabled = true;
    summary.textContent = 'Select your role to continue.';
    return;
  }

  const cfg = ROLE_CONFIG[loginSelectedRole];
  const pageNames = cfg.pages.map(k => PAGES[k].label).join(', ');
  btn.disabled = false;
  summary.innerHTML = `<strong>${esc(loginSelectedRole)}</strong> &mdash; ${esc(cfg.summary)}<br>Pages available: ${esc(pageNames)}.`;
}

function renderPermissionMatrix() {
  const body = document.getElementById('matrixBody');
  if (!body) return;

  const roles = Object.keys(ROLE_CONFIG);
  body.innerHTML = Object.keys(PERMISSION_MATRIX).map(k => `
    <tr>
      <td><strong>${esc(PERMISSION_MATRIX[k].label)}</strong></td>
      ${roles.map(r => {
        const ok = PERMISSION_MATRIX[k].roles[r].allow;
        const hl = r === loginSelectedRole ? ' ac-col-active' : '';
        return `<td class="${ok ? 'perm-allow' : 'perm-deny'}${hl}">${ok ? '&#10003; ALLOW' : '&#10005; DENIED'}</td>`;
      }).join('')}
    </tr>
  `).join('');

  document.querySelectorAll('#matrixHead th[data-role]').forEach(th => {
    th.classList.toggle('ac-col-active', th.dataset.role === loginSelectedRole);
  });
}

function submitLogin() {
  if (!loginSelectedRole) {
    showToast('Please select a role first.');
    return;
  }

  const nameInput = document.getElementById('loginName');
  const name = nameInput.value.replace(/[<>]/g, '').trim().slice(0, 40);
  if (!name) {
    showToast('Please enter your name to continue.');
    nameInput.focus();
    return;
  }

  try {
    setSession({ name: name, role: loginSelectedRole, since: Date.now() });
  } catch (e) {
    showToast('Your browser blocked session storage. Please allow storage for this page.');
    return;
  }

  appendCustodyLog(`${name} (${loginSelectedRole})`, 'Role Login', `Role: ${loginSelectedRole}`, 'Access Granted');
  window.location.href = ROLE_CONFIG[loginSelectedRole].landing;
}

// ----------------------------------------------------------------------------
// 1. DEFAULT DATA & LOCAL STORAGE MANAGEMENT
// ----------------------------------------------------------------------------

const DEFAULT_EVIDENCE = [
  {
    id: 'EVD-001',
    name: 'memory_dump_win11.raw',
    caseNum: 'CASE-2026-081',
    officer: 'Officer Alex Turner',
    uploadedAt: '2026-10-17 08:30 UTC',
    baselineHash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    currentHash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    isTampered: false
  },
  {
    id: 'EVD-002',
    name: 'network_traffic_capture.pcap',
    caseNum: 'CASE-2026-081',
    officer: 'Officer Alex Turner',
    uploadedAt: '2026-10-17 09:15 UTC',
    baselineHash: 'a94a8fe5ccb19ba61c4c0873d391e987982fbbd377b5a1b32d36ab2b75712f5a',
    currentHash: 'a94a8fe5ccb19ba61c4c0873d391e987982fbbd377b5a1b32d36ab2b75712f5a',
    isTampered: false
  },
  {
    id: 'EVD-003',
    name: 'windows_security_events.evtx',
    caseNum: 'CASE-2026-081',
    officer: 'Analyst Jordan Lee',
    uploadedAt: '2026-10-17 10:45 UTC',
    baselineHash: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
    currentHash: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
    isTampered: false
  }
];

const DEFAULT_LOGS = [
  {
    id: 'LOG-101',
    time: '2026-10-17 08:30 UTC',
    officer: 'Officer Alex Turner',
    action: 'Evidence Ingestion',
    target: 'EVD-001 (memory_dump_win11.raw)',
    status: 'Hash Sealed'
  },
  {
    id: 'LOG-102',
    time: '2026-10-17 09:15 UTC',
    officer: 'Officer Alex Turner',
    action: 'Evidence Ingestion',
    target: 'EVD-002 (network_traffic_capture.pcap)',
    status: 'Hash Sealed'
  },
  {
    id: 'LOG-103',
    time: '2026-10-17 09:40 UTC',
    officer: 'Analyst Jordan Lee',
    action: 'Integrity Verification',
    target: 'EVD-001 (memory_dump_win11.raw)',
    status: 'Verified Intact'
  },
  {
    id: 'LOG-104',
    time: '2026-10-17 10:45 UTC',
    officer: 'Analyst Jordan Lee',
    action: 'Evidence Ingestion',
    target: 'EVD-003 (windows_security_events.evtx)',
    status: 'Hash Sealed'
  },
  {
    id: 'LOG-105',
    time: '2026-10-17 11:20 UTC',
    officer: 'Auditor Morgan Hayes',
    action: 'Custody Log Inspection',
    target: 'Case File CASE-2026-081',
    status: 'Audit Reviewed'
  }
];

function getStoredEvidence() {
  const data = localStorage.getItem('forensic_evidence_list');
  return data ? JSON.parse(data) : DEFAULT_EVIDENCE;
}

function saveStoredEvidence(evidenceList) {
  localStorage.setItem('forensic_evidence_list', JSON.stringify(evidenceList));
}

function getStoredLogs() {
  const data = localStorage.getItem('forensic_custody_logs');
  return data ? JSON.parse(data) : DEFAULT_LOGS;
}

function saveStoredLogs(logsList) {
  localStorage.setItem('forensic_custody_logs', JSON.stringify(logsList));
}

function appendCustodyLog(officer, action, target, status) {
  const logs = getStoredLogs();
  const nextNum = logs.length + 101;
  const newEntry = {
    id: `LOG-${nextNum}`,
    time: new Date().toISOString().replace('T', ' ').substring(0, 16) + ' UTC',
    officer: officer || 'Investigator',
    action: action,
    target: target,
    status: status
  };
  logs.unshift(newEntry);
  saveStoredLogs(logs);
}

// ----------------------------------------------------------------------------
// 2. CRYPTOGRAPHIC SHA-256 (WEB CRYPTO API)
// ----------------------------------------------------------------------------

async function calculateSHA256(arrayBuffer) {
  const hashBuffer = await window.crypto.subtle.digest('SHA-256', arrayBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// ----------------------------------------------------------------------------
// 3. PAGE 1: EVIDENCE VAULT (index.html)
// ----------------------------------------------------------------------------

function initEvidencePage() {
  if (!guardPage('vault')) return;

  // The logged-in user is the investigator of record (cannot be typed over).
  const officerInput = document.getElementById('investigatorName');
  if (officerInput) {
    officerInput.value = currentUserName();
    officerInput.readOnly = true;
  }

  renderEvidenceList();
  applyPermissionLocks();
}

function renderEvidenceList() {
  const container = document.getElementById('evidenceContainer');
  if (!container) return;

  const evidence = getStoredEvidence();
  container.innerHTML = evidence.map(item => `
    <div class="evidence-card">
      <div class="evidence-header">
        <div class="evidence-title-area">
          <div class="evidence-filename">${esc(item.name)}</div>
          <div class="evidence-meta">ID: ${esc(item.id)} | Case: ${esc(item.caseNum)} | Ingested by: ${esc(item.officer)} on ${esc(item.uploadedAt)}</div>
        </div>
        <div>
          ${item.isTampered 
            ? '<span class="status-tag tampered">✕ TAMPERED / HASH MISMATCH</span>' 
            : '<span class="status-tag verified">✓ VERIFIED INTACT</span>'
          }
        </div>
      </div>

      <div class="hash-container">
        <div class="hash-label">SHA-256 Cryptographic Hash:</div>
        <div class="hash-value">${esc(item.currentHash)}</div>
      </div>

      <div class="evidence-actions">
        <a href="integrity-verifier.html" class="btn btn-secondary btn-sm">
          Inspect in Verifier Lab →
        </a>
        <button class="btn btn-danger btn-sm" data-perm="SIMULATE_TAMPER" onclick="quickTamper('${item.id}')">
          Simulate Tampering
        </button>
        <button class="btn btn-secondary btn-sm" data-perm="SIMULATE_TAMPER" onclick="quickRestore('${item.id}')">
          Restore Original
        </button>
      </div>
    </div>
  `).join('');

  // Re-apply role locks to the freshly drawn buttons, and to the verifier link.
  applyPermissionLocks();
  lockRestrictedLinks(currentRole());
}

async function handleEvidenceUpload() {
  if (!requirePerm('UPLOAD_EVIDENCE')) return;

  const fileInput = document.getElementById('fileUploadInput');
  const caseInput = document.getElementById('caseNumber');

  if (!fileInput.files || fileInput.files.length === 0) {
    showToast('Please select a file to ingest first.');
    return;
  }

  const file = fileInput.files[0];
  const officer = currentUserName();
  const caseNum = caseInput.value.trim() || 'CASE-2026-081';

  showToast(`Generating SHA-256 for "${file.name}"...`);

  try {
    const arrayBuffer = await file.arrayBuffer();
    const hash = await calculateSHA256(arrayBuffer);

    const evidence = getStoredEvidence();
    const newId = `EVD-00${evidence.length + 1}`;

    const newEvidenceItem = {
      id: newId,
      name: file.name,
      caseNum: caseNum,
      officer: officer,
      uploadedAt: new Date().toISOString().replace('T', ' ').substring(0, 16) + ' UTC',
      baselineHash: hash,
      currentHash: hash,
      isTampered: false
    };

    evidence.unshift(newEvidenceItem);
    saveStoredEvidence(evidence);

    appendCustodyLog(currentActor(), 'Evidence Ingestion', `${newId} (${file.name})`, 'Hash Sealed');

    renderEvidenceList();
    fileInput.value = '';
    showToast(`File "${file.name}" successfully ingested and hashed!`);
  } catch (err) {
    console.error(err);
    showToast('Error hashing file: ' + err.message);
  }
}

function resetToSampleEvidence() {
  if (!requirePerm('UPLOAD_EVIDENCE')) return;

  if (confirm('Reset evidence locker to default sample items?')) {
    saveStoredEvidence(DEFAULT_EVIDENCE);
    saveStoredLogs(DEFAULT_LOGS);
    renderEvidenceList();
    showToast('Evidence locker reset to sample data.');
  }
}

// ----------------------------------------------------------------------------
// 4. PAGE 2: INTEGRITY VERIFIER (integrity-verifier.html)
// ----------------------------------------------------------------------------

function initVerifierPage() {
  if (!guardPage('verifier')) return;

  populateTestSelect();
  applyPermissionLocks();
}

function populateTestSelect() {
  const select = document.getElementById('selectEvidenceToTest');
  if (!select) return;

  const evidence = getStoredEvidence();
  select.innerHTML = evidence.map(item => `
    <option value="${esc(item.id)}">
      [${esc(item.id)}] ${esc(item.name)}
    </option>
  `).join('');

  select.onchange = () => {
    updateTestBoxes();
  };

  updateTestBoxes();
}

function updateTestBoxes() {
  const select = document.getElementById('selectEvidenceToTest');
  if (!select) return;

  const evidence = getStoredEvidence();
  const selectedItem = evidence.find(i => i.id === select.value) || evidence[0];

  if (selectedItem) {
    document.getElementById('testBaselineHash').textContent = selectedItem.baselineHash;
    document.getElementById('testCurrentHash').textContent = selectedItem.currentHash;

    const verdict = document.getElementById('verdictDisplay');
    if (selectedItem.baselineHash === selectedItem.currentHash) {
      verdict.className = 'verdict-box intact';
      verdict.innerHTML = '✓ INTEGRITY VERIFIED: Hashes match perfectly. Evidence is authentic and unmodified.';
    } else {
      verdict.className = 'verdict-box altered';
      verdict.innerHTML = '✕ CRITICAL ALERT: The live file hash does NOT match the stored baseline! Tampering detected.';
    }
  }
}

function verifyActiveItem() {
  if (!requirePerm('VERIFY_INTEGRITY')) return;

  const select = document.getElementById('selectEvidenceToTest');
  const evidence = getStoredEvidence();
  const item = evidence.find(i => i.id === select.value);
  if (!item) return;

  const isMatch = (item.baselineHash === item.currentHash);
  appendCustodyLog(
    currentActor(),
    'Integrity Verification',
    `${item.id} (${item.name})`,
    isMatch ? 'Verified Intact' : 'Tamper Detected'
  );

  updateTestBoxes();
  showToast(isMatch ? 'Evidence verified intact!' : 'Alert: Evidence hash mismatch!');
}

function simulateTamperActiveItem() {
  const select = document.getElementById('selectEvidenceToTest');
  quickTamper(select.value);
}

function quickTamper(evidenceId) {
  if (!requirePerm('SIMULATE_TAMPER')) return;

  const evidence = getStoredEvidence();
  const item = evidence.find(i => i.id === evidenceId);
  if (!item) return;

  item.currentHash = 'b90e872c' + item.baselineHash.substring(8, 56) + 'fa1100bc';
  item.isTampered = true;

  saveStoredEvidence(evidence);
  appendCustodyLog(currentActor(), 'Simulated Tampering', `${item.id} (${item.name})`, 'Tamper Simulated');

  if (document.getElementById('evidenceContainer')) renderEvidenceList();
  if (document.getElementById('selectEvidenceToTest')) updateTestBoxes();

  showToast(`Simulated tampering on "${item.name}". Hash modified!`);
}

function restoreActiveItem() {
  const select = document.getElementById('selectEvidenceToTest');
  quickRestore(select.value);
}

function quickRestore(evidenceId) {
  if (!requirePerm('SIMULATE_TAMPER')) return;

  const evidence = getStoredEvidence();
  const item = evidence.find(i => i.id === evidenceId);
  if (!item) return;

  item.currentHash = item.baselineHash;
  item.isTampered = false;

  saveStoredEvidence(evidence);
  appendCustodyLog(currentActor(), 'Restore Evidence File', `${item.id} (${item.name})`, 'Restored');

  if (document.getElementById('evidenceContainer')) renderEvidenceList();
  if (document.getElementById('selectEvidenceToTest')) updateTestBoxes();

  showToast(`Restored authentic baseline hash for "${item.name}".`);
}

// ----------------------------------------------------------------------------
// 5. PAGE 3: CHAIN OF CUSTODY (chain-of-custody.html)
// ----------------------------------------------------------------------------

function initCustodyPage() {
  if (!guardPage('custody')) return;

  // Opening the ledger is itself a loggable "inspection" action.
  if (!requirePerm('VIEW_LOGS')) return;

  renderCustodyTable();
  updateCustodyStats();
  applyPermissionLocks();
}

function renderCustodyTable() {
  const tbody = document.getElementById('custodyTableBody');
  if (!tbody) return;

  const logs = getStoredLogs();
  tbody.innerHTML = logs.map(log => {
    let statusClass = 'verified';
    if (log.status.includes('Tamper') || log.status.includes('Denied')) statusClass = 'tampered';

    return `
      <tr>
        <td style="font-family: var(--font-mono); font-weight: 600; color: var(--cyan);">${esc(log.id)}</td>
        <td style="font-size: 0.82rem; color: var(--text-secondary);">${esc(log.time)}</td>
        <td style="font-weight: 500;">${esc(log.officer)}</td>
        <td><span style="font-weight: 600;">${esc(log.action)}</span></td>
        <td style="font-size: 0.85rem; color: var(--text-secondary);">${esc(log.target)}</td>
        <td>
          <span class="status-tag ${statusClass}">${esc(log.status)}</span>
        </td>
      </tr>
    `;
  }).join('');
}

function updateCustodyStats() {
  const evidence = getStoredEvidence();
  const logs = getStoredLogs();

  const countEl = document.getElementById('statEvidenceCount');
  const logEl = document.getElementById('statLogCount');

  if (countEl) countEl.textContent = evidence.length;
  if (logEl) logEl.textContent = logs.length;
}

function exportCustodyCSV() {
  if (!requirePerm('EXPORT_CERT')) return;

  const logs = getStoredLogs();
  const headers = ['Log_ID', 'Date_Time_UTC', 'Investigator', 'Action', 'Target_Evidence', 'Status'];
  const rows = logs.map(l => [
    l.id,
    `"${l.time}"`,
    `"${l.officer}"`,
    `"${l.action}"`,
    `"${l.target.replace(/"/g, '""')}"`,
    `"${l.status}"`
  ]);

  const csv = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'Chain_of_Custody_Log_CASE-2026-081.csv';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);

  appendCustodyLog(currentActor(), 'Ledger Export (CSV)', 'Case File CASE-2026-081', 'Exported');
  renderCustodyTable();
  updateCustodyStats();

  showToast('Chain of Custody CSV log downloaded.');
}

function printCourtCertificate() {
  if (!requirePerm('EXPORT_CERT')) return;

  appendCustodyLog(currentActor(), 'Court Certificate Print', 'Case File CASE-2026-081', 'Exported');
  renderCustodyTable();
  updateCustodyStats();
  window.print();
}

// ----------------------------------------------------------------------------
// 4. ACCESS CONTROL CONSOLE (rbac-console.html)
// ----------------------------------------------------------------------------
function initRbacPage() {
  if (!guardPage('rbac')) return;
  renderRbacPage();
}

function renderRbacPage() {
  const role = currentRole();
  const badge = document.getElementById('currentRoleBadge');
  if (badge) badge.textContent = `Active Role: ${role}`;

  const sel = document.getElementById('rbacRoleSelector');
  if (sel) sel.value = role;

  const body = document.getElementById('rbacMatrixBody');
  if (body) {
    const roles = Object.keys(ROLE_CONFIG);
    body.innerHTML = Object.keys(PERMISSION_MATRIX).map(k => `
      <tr>
        <td><strong>${esc(PERMISSION_MATRIX[k].label)}</strong></td>
        ${roles.map(r => {
          const ok = PERMISSION_MATRIX[k].roles[r].allow;
          const hl = r === role ? ' ac-col-active' : '';
          return `<td class="${ok ? 'perm-allow' : 'perm-deny'}${hl}">${ok ? '&#10003; ALLOW' : '&#10005; DENIED'}</td>`;
        }).join('')}
      </tr>
    `).join('');
  }
  document.querySelectorAll('#rbacMatrixHead th[data-role]').forEach(th => {
    th.classList.toggle('ac-col-active', th.dataset.role === role);
  });
}

// Switch the active role for this tab (keeps the same user name).
function switchRbacRole(newRole) {
  const session = getSession();
  if (!session || !ROLE_CONFIG[newRole] || session.role === newRole) return;
  const oldRole = session.role;
  setSession({ name: session.name, role: newRole, since: Date.now() });
  appendCustodyLog(`${session.name} (${newRole})`, 'Role Switch', `${oldRole} -> ${newRole}`, 'Access Granted');
  window.location.reload();
}

// Try one permission as the current role and show the result (denials are logged).
function testRbacAction(permKey) {
  const box = document.getElementById('rbacFeedbackBox');
  const entry = PERMISSION_MATRIX[permKey];
  if (!box || !entry) return;

  const role = currentRole();
  const allowed = requirePerm(permKey);
  box.className = 'verdict-box ' + (allowed ? 'intact' : 'altered');
  box.innerHTML = allowed
    ? `<strong>&#10003; ALLOWED</strong> &mdash; ${esc(role)} may: ${esc(entry.label)}.<br>${esc(entry.roles[role].reason)}`
    : `<strong>&#10005; ACCESS DENIED</strong> &mdash; ${esc(role)} may not: ${esc(entry.label)}.<br>${esc(entry.roles[role].reason)}<br><em>This attempt was written to the chain of custody log.</em>`;
}

// ----------------------------------------------------------------------------
// 6. PAGE 4: 2FA & SANITIZATION (security-gateway.html)
// ----------------------------------------------------------------------------

let currentTotp = '582914';

function initSecurityGatePage() {
  if (!guardPage('security')) return;

  setupSanitizationInspector();
  startTotpClock();
  applyPermissionLocks();
}

function setupSanitizationInspector() {
  const input = document.getElementById('sanitizeTestInput');
  if (!input) return;

  const runSanitization = () => {
    const raw = input.value;
    let clean = raw.replace(/(\.\.[\/\\])+/g, ''); // strip ../
    clean = clean.replace(/[<>:"/\\|?*]/g, '_');    // strip illegal chars
    clean = clean.replace(/<[^>]*>?/gm, '');       // strip HTML tags

    const hasTraversal = /(\.\.[\/\\])+/g.test(raw);

    document.getElementById('previewOriginal').textContent = raw || '(empty)';
    document.getElementById('previewClean').textContent = clean || 'sanitized_file.bin';
    document.getElementById('previewDefense').textContent = hasTraversal 
      ? 'BLOCKED (Path climbing stripped)' 
      : 'CLEAN (Safe destination path)';
    document.getElementById('previewDefense').style.color = hasTraversal ? 'var(--emerald)' : 'var(--cyan)';
  };

  input.addEventListener('input', runSanitization);
  runSanitization();
}

function setSanitizeSample(sampleText) {
  const input = document.getElementById('sanitizeTestInput');
  if (input) {
    input.value = sampleText;
    input.dispatchEvent(new Event('input'));
  }
}

function startTotpClock() {
  const updateTotp = () => {
    const now = Math.floor(Date.now() / 1000);
    const windowSeconds = 30;
    const timeStep = Math.floor(now / windowSeconds);
    const remaining = windowSeconds - (now % windowSeconds);

    const pseudoCode = Math.floor(Math.abs(Math.sin(timeStep * 8888)) * 900000 + 100000).toString();
    currentTotp = pseudoCode;

    const codeEl = document.getElementById('totpLiveCode');
    const timerEl = document.getElementById('totpTimerText');

    if (codeEl) codeEl.textContent = `${pseudoCode.substring(0, 3)} ${pseudoCode.substring(3)}`;
    if (timerEl) timerEl.textContent = `Refreshing in ${remaining} seconds`;
  };

  updateTotp();
  setInterval(updateTotp, 1000);
}

function validateUserTotp() {
  const input = document.getElementById('totpInput');
  const feedback = document.getElementById('totpFeedback');
  if (!input || !feedback) return;

  const userCode = input.value.trim().replace(/\s+/g, '');
  if (userCode === currentTotp) {
    if (can('TRANSFER_CUSTODY')) {
      feedback.className = 'verdict-box intact';
      feedback.innerHTML = '✓ <strong>2FA TOKEN ACCEPTED</strong>: Time-synchronized token verified. Custody transfer authorized for your role.';
      appendCustodyLog(currentActor(), '2FA Authentication', 'Session Gate', 'Authorized (TOTP Valid)');
    } else {
      feedback.className = 'verdict-box intact';
      feedback.innerHTML = `✓ <strong>2FA TOKEN ACCEPTED</strong>, but the <strong>${esc(currentRole())}</strong> role cannot transfer custody. ${esc(permReason('TRANSFER_CUSTODY'))}`;
      appendCustodyLog(currentActor(), '2FA Authentication', 'Session Gate', 'Token Valid (No Transfer Rights)');
    }
    showToast('2FA Verification Successful!');
  } else {
    feedback.className = 'verdict-box altered';
    feedback.innerHTML = `✕ <strong>INVALID CODE</strong>: The token entered does not match current rolling window code (${currentTotp.substring(0,3)} ${currentTotp.substring(3)}).`;
    showToast('2FA Verification Failed');
  }
}

// ----------------------------------------------------------------------------
// 7. TOAST NOTIFICATIONS
// ----------------------------------------------------------------------------

function showToast(msg) {
  const toast = document.getElementById('toastNotification');
  if (!toast) return;

  toast.textContent = msg;
  toast.style.display = 'block';

  clearTimeout(toast.timeoutId);
  toast.timeoutId = setTimeout(() => {
    toast.style.display = 'none';
  }, 3500);
}
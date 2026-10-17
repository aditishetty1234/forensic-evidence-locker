/**
 * FORENSIC EVIDENCE LOCKER - APPLICATION LOGIC
 * Shared between all 5 web pages:
 * Page 1: index.html (Evidence Vault)
 * Page 2: integrity-verifier.html (Integrity Lab)
 * Page 3: chain-of-custody.html (Audit Ledger)
 * Page 4: rbac-console.html (Access Control)
 * Page 5: security-gateway.html (2FA & Sanitization)
 */

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
  renderEvidenceList();
}

function renderEvidenceList() {
  const container = document.getElementById('evidenceContainer');
  if (!container) return;

  const evidence = getStoredEvidence();
  container.innerHTML = evidence.map(item => `
    <div class="evidence-card">
      <div class="evidence-header">
        <div class="evidence-title-area">
          <div class="evidence-filename">${item.name}</div>
          <div class="evidence-meta">ID: ${item.id} | Case: ${item.caseNum} | Ingested by: ${item.officer} on ${item.uploadedAt}</div>
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
        <div class="hash-value">${item.currentHash}</div>
      </div>

      <div class="evidence-actions">
        <a href="integrity-verifier.html" class="btn btn-secondary btn-sm">
          Inspect in Verifier Lab →
        </a>
        <button class="btn btn-danger btn-sm" onclick="quickTamper('${item.id}')">
          Simulate Tampering
        </button>
        <button class="btn btn-secondary btn-sm" onclick="quickRestore('${item.id}')">
          Restore Original
        </button>
      </div>
    </div>
  `).join('');
}

async function handleEvidenceUpload() {
  const fileInput = document.getElementById('fileUploadInput');
  const officerInput = document.getElementById('investigatorName');
  const caseInput = document.getElementById('caseNumber');

  if (!fileInput.files || fileInput.files.length === 0) {
    showToast('Please select a file to ingest first.');
    return;
  }

  const file = fileInput.files[0];
  const officer = officerInput.value.trim() || 'Officer Alex Turner';
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

    appendCustodyLog(officer, 'Evidence Ingestion', `${newId} (${file.name})`, 'Hash Sealed');

    renderEvidenceList();
    fileInput.value = '';
    showToast(`File "${file.name}" successfully ingested and hashed!`);
  } catch (err) {
    console.error(err);
    showToast('Error hashing file: ' + err.message);
  }
}

function resetToSampleEvidence() {
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
  populateTestSelect();
}

function populateTestSelect() {
  const select = document.getElementById('selectEvidenceToTest');
  if (!select) return;

  const evidence = getStoredEvidence();
  select.innerHTML = evidence.map(item => `
    <option value="${item.id}">
      [${item.id}] ${item.name}
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
  const select = document.getElementById('selectEvidenceToTest');
  const evidence = getStoredEvidence();
  const item = evidence.find(i => i.id === select.value);
  if (!item) return;

  const isMatch = (item.baselineHash === item.currentHash);
  appendCustodyLog(
    'Officer Alex Turner',
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
  const evidence = getStoredEvidence();
  const item = evidence.find(i => i.id === evidenceId);
  if (!item) return;

  item.currentHash = 'b90e872c' + item.baselineHash.substring(8, 56) + 'fa1100bc';
  item.isTampered = true;

  saveStoredEvidence(evidence);
  appendCustodyLog('Officer Alex Turner', 'Simulated Tampering', `${item.id} (${item.name})`, 'Tamper Simulated');

  if (document.getElementById('evidenceContainer')) renderEvidenceList();
  if (document.getElementById('selectEvidenceToTest')) updateTestBoxes();

  showToast(`Simulated tampering on "${item.name}". Hash modified!`);
}

function restoreActiveItem() {
  const select = document.getElementById('selectEvidenceToTest');
  quickRestore(select.value);
}

function quickRestore(evidenceId) {
  const evidence = getStoredEvidence();
  const item = evidence.find(i => i.id === evidenceId);
  if (!item) return;

  item.currentHash = item.baselineHash;
  item.isTampered = false;

  saveStoredEvidence(evidence);
  appendCustodyLog('Officer Alex Turner', 'Restore Evidence File', `${item.id} (${item.name})`, 'Restored');

  if (document.getElementById('evidenceContainer')) renderEvidenceList();
  if (document.getElementById('selectEvidenceToTest')) updateTestBoxes();

  showToast(`Restored authentic baseline hash for "${item.name}".`);
}

// ----------------------------------------------------------------------------
// 5. PAGE 3: CHAIN OF CUSTODY (chain-of-custody.html)
// ----------------------------------------------------------------------------

function initCustodyPage() {
  renderCustodyTable();
  updateCustodyStats();
}

function renderCustodyTable() {
  const tbody = document.getElementById('custodyTableBody');
  if (!tbody) return;

  const logs = getStoredLogs();
  tbody.innerHTML = logs.map(log => {
    let statusClass = 'verified';
    if (log.status.includes('Tamper')) statusClass = 'tampered';

    return `
      <tr>
        <td style="font-family: var(--font-mono); font-weight: 600; color: var(--cyan);">${log.id}</td>
        <td style="font-size: 0.82rem; color: var(--text-secondary);">${log.time}</td>
        <td style="font-weight: 500;">${log.officer}</td>
        <td><span style="font-weight: 600;">${log.action}</span></td>
        <td style="font-size: 0.85rem; color: var(--text-secondary);">${log.target}</td>
        <td>
          <span class="status-tag ${statusClass}">${log.status}</span>
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

  showToast('Chain of Custody CSV log downloaded.');
}

// ----------------------------------------------------------------------------
// 6. PAGE 4: RBAC CONSOLE (rbac-console.html)
// ----------------------------------------------------------------------------

let currentActiveRole = 'Lead Investigator';

function initRbacPage() {
  const selector = document.getElementById('rbacRoleSelector');
  if (!selector) return;

  selector.value = currentActiveRole;
  selector.addEventListener('change', (e) => {
    currentActiveRole = e.target.value;
    document.getElementById('currentRoleBadge').textContent = `Active Role: ${currentActiveRole}`;
    showToast(`Role switched to: ${currentActiveRole}`);
  });
}

function testRbacAction(actionKey) {
  const feedback = document.getElementById('rbacFeedbackBox');
  if (!feedback) return;

  const permissions = {
    'UPLOAD_EVIDENCE': {
      'Lead Investigator': { allow: true, reason: 'Lead Investigators hold full evidentiary ingestion rights.' },
      'Forensic Analyst': { allow: false, reason: 'Forensic Analysts have read/verify rights only (Least Privilege Policy).' },
      'Compliance Auditor': { allow: false, reason: 'Auditors are restricted from creating or modifying evidence.' }
    },
    'VERIFY_INTEGRITY': {
      'Lead Investigator': { allow: true, reason: 'Lead Investigators can run cryptographic verifications.' },
      'Forensic Analyst': { allow: true, reason: 'Forensic Analysts are authorized to compute & verify hashes.' },
      'Compliance Auditor': { allow: false, reason: 'Auditors inspect custody logs, not active evidence files.' }
    },
    'SIMULATE_TAMPER': {
      'Lead Investigator': { allow: true, reason: 'Authorized for security research and vulnerability demonstration.' },
      'Forensic Analyst': { allow: false, reason: 'Analysts cannot execute file alteration routines.' },
      'Compliance Auditor': { allow: false, reason: 'Strictly prohibited from tampering with evidence.' }
    },
    'VIEW_LOGS': {
      'Lead Investigator': { allow: true, reason: 'Access granted to audit trail.' },
      'Forensic Analyst': { allow: true, reason: 'Access granted to audit trail.' },
      'Compliance Auditor': { allow: true, reason: 'Primary responsibility: independent compliance review.' }
    },
    'TRANSFER_CUSTODY': {
      'Lead Investigator': { allow: true, reason: 'Permitted upon secondary TOTP 2FA approval.' },
      'Forensic Analyst': { allow: false, reason: 'Cannot transfer legal custody between agencies.' },
      'Compliance Auditor': { allow: false, reason: 'Cannot transfer custody.' }
    }
  };

  const check = permissions[actionKey][currentActiveRole];
  if (check.allow) {
    feedback.className = 'verdict-box intact';
    feedback.innerHTML = `✓ <strong>PERMISSION GRANTED</strong> for <code>${actionKey}</code>.<br><span style="font-size: 0.85rem; font-weight: normal;">${check.reason}</span>`;
  } else {
    feedback.className = 'verdict-box altered';
    feedback.innerHTML = `✕ <strong>ACCESS DENIED</strong> for <code>${actionKey}</code> under <strong>${currentActiveRole}</strong>.<br><span style="font-size: 0.85rem; font-weight: normal;">${check.reason}</span>`;
  }
}

// ----------------------------------------------------------------------------
// 7. PAGE 5: 2FA & SANITIZATION (security-gateway.html)
// ----------------------------------------------------------------------------

let currentTotp = '582914';

function initSecurityGatePage() {
  setupSanitizationInspector();
  startTotpClock();
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
    feedback.className = 'verdict-box intact';
    feedback.innerHTML = '✓ <strong>2FA TOKEN ACCEPTED</strong>: Time-synchronized token verified. Sensitive custody operation authorized.';
    showToast('2FA Verification Successful!');
    appendCustodyLog('Officer Alex Turner', '2FA Authentication', 'Session Gate', 'Authorized (TOTP Valid)');
  } else {
    feedback.className = 'verdict-box altered';
    feedback.innerHTML = `✕ <strong>INVALID CODE</strong>: The token entered does not match current rolling window code (${currentTotp.substring(0,3)} ${currentTotp.substring(3)}).`;
    showToast('2FA Verification Failed');
  }
}

// ----------------------------------------------------------------------------
// 8. TOAST NOTIFICATIONS
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

/**
 * FORENSIC EVIDENCE LOCKER - APP LOGIC
 * Shared between Page 1 (index.html) and Page 2 (chain-of-custody.html)
 */

// ----------------------------------------------------------------------------
// DEFAULT DATA & LOCAL STORAGE MANAGEMENT
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
// REAL WEB CRYPTO SHA-256 HASHING
// ----------------------------------------------------------------------------

async function calculateSHA256(arrayBuffer) {
  const hashBuffer = await window.crypto.subtle.digest('SHA-256', arrayBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hexHash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  return hexHash;
}

// ----------------------------------------------------------------------------
// PAGE 1: EVIDENCE LOCKER (index.html)
// ----------------------------------------------------------------------------

function initEvidencePage() {
  renderEvidenceList();
  populateTestSelect();
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
        <button class="btn btn-secondary btn-sm" onclick="selectItemForTesting('${item.id}')">
          Inspect in Verification Test
        </button>
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
      verdict.innerHTML = '✕ INTEGRITY BREACH: The current hash does NOT match the stored baseline hash! Evidence has been altered.';
    }
  }
}

function selectItemForTesting(evidenceId) {
  const select = document.getElementById('selectEvidenceToTest');
  if (select) {
    select.value = evidenceId;
    updateTestBoxes();
    select.scrollIntoView({ behavior: 'smooth' });
  }
}

async function handleEvidenceUpload() {
  const fileInput = document.getElementById('fileUploadInput');
  const officerInput = document.getElementById('investigatorName');
  const caseInput = document.getElementById('caseNumber');

  if (!fileInput.files || fileInput.files.length === 0) {
    showToast('Please select a file to upload first.');
    return;
  }

  const file = fileInput.files[0];
  const officer = officerInput.value.trim() || 'Officer Alex Turner';
  const caseNum = caseInput.value.trim() || 'CASE-2026-081';

  showToast(`Calculating SHA-256 for "${file.name}"...`);

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

    // Record in Chain of Custody Log
    appendCustodyLog(officer, 'Evidence Ingestion', `${newId} (${file.name})`, 'Hash Sealed');

    // Refresh UI
    renderEvidenceList();
    populateTestSelect();
    selectItemForTesting(newId);

    // Reset file input
    fileInput.value = '';

    showToast(`File "${file.name}" saved with SHA-256 hash!`);
  } catch (err) {
    console.error(err);
    showToast('Error generating cryptographic hash: ' + err.message);
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

  // Modify hash
  item.currentHash = 'b90e872c' + item.baselineHash.substring(8, 56) + 'fa1100bc';
  item.isTampered = true;

  saveStoredEvidence(evidence);
  appendCustodyLog('Officer Alex Turner', 'Simulated Tampering', `${item.id} (${item.name})`, 'Tamper Simulated');

  renderEvidenceList();
  updateTestBoxes();
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

  renderEvidenceList();
  updateTestBoxes();
  showToast(`Restored original authentic hash for "${item.name}".`);
}

function resetToSampleEvidence() {
  if (confirm('Reset evidence locker to default sample items?')) {
    saveStoredEvidence(DEFAULT_EVIDENCE);
    saveStoredLogs(DEFAULT_LOGS);
    renderEvidenceList();
    populateTestSelect();
    showToast('Evidence locker reset to sample data.');
  }
}

// ----------------------------------------------------------------------------
// PAGE 2: CHAIN OF CUSTODY (chain-of-custody.html)
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
// TOAST NOTIFICATIONS
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

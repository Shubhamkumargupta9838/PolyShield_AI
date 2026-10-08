const API_BASE_URL = '/api/v1';

function getOrigin() {
  return typeof window !== 'undefined' && window.location && window.location.origin && window.location.origin !== 'null'
    ? window.location.origin
    : 'http://localhost:5173';
}

export async function fetchHealthStatus() {
  try {
    const origin = getOrigin();
    const response = await fetch(`${origin}${API_BASE_URL}/health`);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
  } catch (error) {
    return {
      status: 'offline',
      system: 'PolyShield AI',
      error: error.message
    };
  }
}

export async function createScan(metadata) {
  const origin = getOrigin();
  const response = await fetch(`${origin}${API_BASE_URL}/scans`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(metadata)
  });
  if (!response.ok) {
    const errData = await response.json().catch(() => ({}));
    throw new Error(errData.message || `Failed to create scan (${response.status})`);
  }
  return await response.json();
}

export async function fetchScans(page = 1, pageSize = 10) {
  try {
    const origin = getOrigin();
    const response = await fetch(`${origin}${API_BASE_URL}/scans?page=${page}&page_size=${pageSize}`);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
  } catch (error) {
    console.error('Failed to fetch scans list:', error);
    return { items: [], total: 0, page: 1, page_size: pageSize, total_pages: 0 };
  }
}

export async function fetchScanById(scanId) {
  const origin = getOrigin();
  const response = await fetch(`${origin}${API_BASE_URL}/scans/${scanId}`);
  if (!response.ok) {
    const errData = await response.json().catch(() => ({}));
    throw new Error(errData.message || `Scan not found (${response.status})`);
  }
  return await response.json();
}

export async function updateScanStatus(scanId, newStatus, errorInfo = null) {
  const origin = getOrigin();
  const response = await fetch(`${origin}${API_BASE_URL}/scans/${scanId}/status`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status: newStatus, error_information: errorInfo })
  });
  if (!response.ok) {
    const errData = await response.json().catch(() => ({}));
    throw new Error(errData.message || `Failed to update status (${response.status})`);
  }
  return await response.json();
}

export async function performStaticAnalysis(scanId, file) {
  const origin = getOrigin();
  const formData = new FormData();
  formData.append('file', file);

  const response = await fetch(`${origin}${API_BASE_URL}/scans/${scanId}/static-analysis`, {
    method: 'POST',
    body: formData
  });
  if (!response.ok) {
    const errData = await response.json().catch(() => ({}));
    throw new Error(errData.message || `Static analysis failed (${response.status})`);
  }
  return await response.json();
}

export async function analyzeScan(scanId, file) {
  const origin = getOrigin();
  const formData = new FormData();
  formData.append('file', file);

  const response = await fetch(`${origin}${API_BASE_URL}/scans/${scanId}/analyze`, {
    method: 'POST',
    body: formData
  });
  if (!response.ok) {
    const errData = await response.json().catch(() => ({}));
    throw new Error(errData.message || errData.detail || `Scan analysis failed (${response.status})`);
  }
  return await response.json();
}

export async function fetchScanReport(scanId) {
  const origin = getOrigin();
  const response = await fetch(`${origin}${API_BASE_URL}/scans/${scanId}/report`);
  if (!response.ok) {
    const errData = await response.json().catch(() => ({}));
    throw new Error(errData.message || errData.detail || `Report not found (${response.status})`);
  }
  return await response.json();
}

export async function triggerDynamicAnalysis(scanId) {
  const origin = getOrigin();
  const response = await fetch(`${origin}${API_BASE_URL}/scans/${scanId}/dynamic-analysis`, {
    method: 'POST'
  });
  if (!response.ok) {
    const errData = await response.json().catch(() => ({}));
    throw new Error(errData.message || errData.detail || `Failed to trigger dynamic analysis (${response.status})`);
  }
  return await response.json();
}

export async function fetchDynamicAnalysis(scanId) {
  const origin = getOrigin();
  const response = await fetch(`${origin}${API_BASE_URL}/scans/${scanId}/dynamic-analysis`);
  if (!response.ok) {
    const errData = await response.json().catch(() => ({}));
    throw new Error(errData.message || errData.detail || `Dynamic analysis not found (${response.status})`);
  }
  return await response.json();
}

export async function fetchDynamicArtifacts(scanId) {
  const origin = getOrigin();
  const response = await fetch(`${origin}${API_BASE_URL}/scans/${scanId}/dynamic-analysis/artifacts`);
  if (!response.ok) {
    const errData = await response.json().catch(() => ({}));
    throw new Error(errData.message || errData.detail || `Artifacts not found (${response.status})`);
  }
  return await response.json();
}

export async function runDynamicInference(scanId) {
  const origin = getOrigin();
  const response = await fetch(`${origin}${API_BASE_URL}/scans/${scanId}/dynamic-inference`, {
    method: 'POST'
  });
  if (!response.ok) {
    const errData = await response.json().catch(() => ({}));
    throw new Error(errData.message || errData.detail || `Failed to run dynamic inference (${response.status})`);
  }
  return await response.json();
}

export async function fetchDynamicInference(scanId) {
  const origin = getOrigin();
  const response = await fetch(`${origin}${API_BASE_URL}/scans/${scanId}/dynamic-inference`);
  if (!response.ok) {
    const errData = await response.json().catch(() => ({}));
    throw new Error(errData.message || errData.detail || `Dynamic inference not found (${response.status})`);
  }
  return await response.json();
}

export async function runEnsembleInference(scanId) {
  const origin = getOrigin();
  const response = await fetch(`${origin}${API_BASE_URL}/scans/${scanId}/ensemble-inference`, {
    method: 'POST'
  });
  if (!response.ok) {
    const errData = await response.json().catch(() => ({}));
    throw new Error(errData.message || errData.detail || `Failed to run ensemble inference (${response.status})`);
  }
  return await response.json();
}

export async function fetchEnsembleInference(scanId) {
  const origin = getOrigin();
  const response = await fetch(`${origin}${API_BASE_URL}/scans/${scanId}/ensemble-inference`);
  if (!response.ok) {
    const errData = await response.json().catch(() => ({}));
    throw new Error(errData.message || errData.detail || `Ensemble inference not found (${response.status})`);
  }
  return await response.json();
}

export async function runExplanation(scanId) {
  const origin = getOrigin();
  const response = await fetch(`${origin}${API_BASE_URL}/scans/${scanId}/explanation`, {
    method: 'POST'
  });
  if (!response.ok) {
    const errData = await response.json().catch(() => ({}));
    throw new Error(errData.message || errData.detail || `Failed to generate explanation (${response.status})`);
  }
  return await response.json();
}

export async function fetchExplanation(scanId) {
  const origin = getOrigin();
  const response = await fetch(`${origin}${API_BASE_URL}/scans/${scanId}/explanation`);
  if (!response.ok) {
    const errData = await response.json().catch(() => ({}));
    throw new Error(errData.message || errData.detail || `Explanation not found (${response.status})`);
  }
  return await response.json();
}



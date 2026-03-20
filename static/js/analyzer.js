// ========== Node.js Analysis Module ==========
let currentResult = null;
let graphSvg = null;
let graphG = null;
let graphZoom = null;
let simulation = null;

// Initialize analyzer
export function initAnalyzer() {
  const analyzeBtn = document.getElementById('analyzeBtn');
  const fileInput = document.getElementById('fileInput');
  const uploadCard = document.querySelector('.upload-card');
  const downloadReport = document.getElementById('downloadReport');
  const downloadPOC = document.getElementById('downloadPOC');
  const downloadJson = document.getElementById('downloadJson');
  
  if (analyzeBtn) {
    analyzeBtn.addEventListener('click', handleAnalyze);
  }
  
  if (uploadCard) {
    // Click to upload
    uploadCard.addEventListener('click', () => {
      fileInput.click();
    });
    
    // ========== Drag and Drop Upload ==========
    // Prevent browser default drag behavior
    uploadCard.addEventListener('dragover', (e) => {
      e.preventDefault();
      e.stopPropagation();
      uploadCard.style.borderColor = 'var(--primary)';
      uploadCard.style.backgroundColor = 'var(--gray-50)';
    });
    
    uploadCard.addEventListener('dragleave', (e) => {
      e.preventDefault();
      e.stopPropagation();
      uploadCard.style.borderColor = 'var(--gray-300)';
      uploadCard.style.backgroundColor = 'white';
    });
    
    uploadCard.addEventListener('drop', (e) => {
      e.preventDefault();
      e.stopPropagation();
      uploadCard.style.borderColor = 'var(--gray-300)';
      uploadCard.style.backgroundColor = 'white';
      
      const files = e.dataTransfer.files;
      if (files.length > 0) {
        const file = files[0];
        if (file.name.endsWith('.js')) {
          // Assign dropped file to fileInput
          fileInput.files = files;
          console.log('Dropped file:', file.name);
          
          // Optional: Auto-trigger analysis
          // handleAnalyze();
        } else {
          showNotification('Only .js files are supported', 'error');
        }
      }
    });
  }
  
  if (fileInput) {
    fileInput.addEventListener('change', handleFileSelect);
  }
  
  // Download button events
  if (downloadReport) {
    downloadReport.addEventListener('click', downloadReportHandler);
  }
  
  if (downloadPOC) {
    downloadPOC.addEventListener('click', downloadPOCHandler);
  }
  
  if (downloadJson) {
    downloadJson.addEventListener('click', downloadJsonHandler);
  }
}

// Handle file selection
function handleFileSelect(event) {
  const file = event.target.files[0];
  if (file) {
    console.log('Selected file:', file.name);
    // Can display filename here
  }
}

// Handle analysis
async function handleAnalyze() {
  const fileInput = document.getElementById('fileInput');
  if (!fileInput.files || fileInput.files.length === 0) {
    showNotification('Please select a file first', 'error');
    return;
  }
  
  const formData = new FormData();
  formData.append('file', fileInput.files[0]);
  
  // Show progress
  document.getElementById('progressContainer').style.display = 'block';
  document.getElementById('resultContainer').style.display = 'none';
  updateDebugInfo('Uploading file...');
  
  try {
    // Call real backend API
    const response = await fetch('/upload', {
      method: 'POST',
      body: formData
    });
    
    updateDebugInfo('File upload complete, waiting for analysis results...');
    
    const result = await response.json();
    
    if (response.ok && result.success) {
      updateDebugInfo('Analysis complete, rendering results');
      document.getElementById('progressContainer').style.display = 'none';
      displayResults(result);
    } else {
      throw new Error(result.error || 'Analysis failed');
    }
  } catch (error) {
    document.getElementById('progressContainer').style.display = 'none';
    showNotification('Error: ' + error.message, 'error');
    updateDebugInfo('Error: ' + error.message);
  }
}

// Update debug information
function updateDebugInfo(message) {
  const debugContent = document.getElementById('debugContent');
  if (!debugContent) return;
  
  const timestamp = new Date().toLocaleTimeString();
  debugContent.innerHTML += `[${timestamp}] ${message}<br>`;
  debugContent.scrollTop = debugContent.scrollHeight;
}

// Display analysis results
function displayResults(result) {
  currentResult = result;
  window.currentResult = result;
  
  updateDebugInfo('Processing analysis results');
  
  // Update module name
  const moduleNameEl = document.getElementById('moduleName');
  if (moduleNameEl) moduleNameEl.textContent = result.module_name || 'Unknown Module';
  
  // Display individual analysis modules
  displayNodejsAnalysis(result.nodejs_analysis);
  displayRootcauseAnalysis(result.rootcause_analysis);
  displayExploitAnalysis(result.exploit_analysis);
  displayPOCVerification(result.poc_reachability_report);
  
  // Display graph structure
  if (result.graph_data) {
    updateDebugInfo('Rendering graph structure, data exists');
    renderAnalysisGraph(result.graph_data);
    document.getElementById('graphBadge').textContent = "Loaded";
  } else {
    updateDebugInfo('Error: graph_data does not exist');
    document.getElementById('graphBadge').textContent = "No Data";
  }
  
  // Show download buttons
  const downloadPOCBtn = document.getElementById('downloadPOC');
  if (downloadPOCBtn) {
    downloadPOCBtn.style.display = 
      result.exploit_analysis && result.exploit_analysis.poc_generation ? 'block' : 'none';
  }
  
  // Show result container
  document.getElementById('resultContainer').style.display = 'block';
  
  // Scroll to results area
  document.getElementById('resultContainer').scrollIntoView({ behavior: 'smooth' });
}

// Display Node.js component analysis
function displayNodejsAnalysis(nodejsAnalysis) {
  const nodejsContent = document.getElementById('nodejsContent');
  const nodejsBadge = document.getElementById('nodejsBadge');
  
  if (!nodejsContent) return;
  
  const analysis = nodejsAnalysis.analysis || {};
  const retrievedNodeJs = nodejsAnalysis.retriever_NodeJs || [];
  const keywords = analysis.NodeJsType_keywords || [];
  const summary = analysis.summary || 'No summary';
  
  let html = `
    <div class="card mb-3">
      <div class="card-header bg-info text-white">
        <h5 class="mb-0"><i class="bi bi-info-circle me-2"></i>Analysis Summary</h5>
      </div>
      <div class="card-body">
        <p>${summary}</p>
      </div>
    </div>
  `;
  
  if (keywords.length > 0) {
    html += `
      <div class="card mb-3">
        <div class="card-header">
          <h5 class="mb-0"><i class="bi bi-tags me-2"></i>Extracted Keywords</h5>
        </div>
        <div class="card-body">
          <div class="d-flex flex-wrap gap-2">
            ${keywords.map(k => `<span class="badge bg-primary">${k}</span>`).join('')}
          </div>
        </div>
      </div>
    `;
  }
  
  if (retrievedNodeJs.length > 0) {
    html += `
      <div class="card">
        <div class="card-header">
          <h5 class="mb-0"><i class="bi bi-diagram-3 me-2"></i>Matched Node.js Components (${retrievedNodeJs.length})</h5>
        </div>
        <div class="card-body">
          <div class="list-group">
    `;
    
    retrievedNodeJs.forEach(doc => {
      const nameMatch = doc.match(/Name: (.+?)(?:\n|$)/);
      const patternMatch = doc.match(/Pattern: (.+?)(?:\n|$)/);
      const name = nameMatch ? nameMatch[1] : 'Unknown Component';
      const pattern = patternMatch ? patternMatch[1] : '';
      
      html += `
        <div class="list-group-item">
          <div class="d-flex w-100 justify-content-between">
            <h6 class="mb-1 fw-bold">${name}</h6>
          </div>
          <p class="mb-1 small text-muted">${pattern}</p>
          <pre class="mt-2 small bg-light p-2 rounded" style="max-height: 100px; overflow-y: auto;">${doc.substring(0, 300)}${doc.length > 300 ? '...' : ''}</pre>
        </div>
      `;
    });
    
    html += `
          </div>
        </div>
      </div>
    `;
  } else {
    html += '<div class="alert alert-warning">No Node.js components matched</div>';
  }
  
  nodejsContent.innerHTML = html;
  nodejsBadge.textContent = retrievedNodeJs.length;
}

// Display vulnerability root cause analysis
function displayRootcauseAnalysis(rootcauseAnalysis) {
  const rootcauseContent = document.getElementById('rootcauseContent');
  const rootcauseBadge = document.getElementById('rootcauseBadge');
  
  if (!rootcauseContent) return;
  
  const vulnInfo = rootcauseAnalysis.final_vulnerability || {};
  const retrievedRootcauses = rootcauseAnalysis.retrieved_rootcauses || [];
  
  let html = '';
  
  if (vulnInfo.vulnerability_name) {
    const severity = vulnInfo.confidence_level || 'Medium';
    const severityClass = 
      severity.includes('High') ? 'danger' : 
      severity.includes('Medium') ? 'warning' : 'info';
    
    html += `
      <div class="card mb-3">
        <div class="card-header bg-${severityClass} text-white">
          <h5 class="mb-0"><i class="bi bi-bug me-2"></i>Vulnerability Summary</h5>
        </div>
        <div class="card-body">
          <h4 class="mb-3">${vulnInfo.vulnerability_name || 'Unknown Vulnerability'}</h4>
          <p><strong>Description:</strong> ${vulnInfo.reason || 'No description'}</p>
          <p><strong>Location:</strong> ${vulnInfo.location || 'Unknown'}</p>
          <p><strong>Confidence:</strong> <span class="badge bg-${severityClass}">${severity}</span></p>
    `;
    
    if (vulnInfo.package) {
      html += `<p><strong>Affected Package:</strong> <code>${vulnInfo.package}</code></p>`;
    }
    
    html += `</div></div>`;
    
    if (vulnInfo.code_snippet) {
      html += `
        <div class="card mb-3">
          <div class="card-header">
            <h5 class="mb-0"><i class="bi bi-code-square me-2"></i>Code Snippet</h5>
          </div>
          <div class="card-body">
            <pre><code class="language-javascript">${escapeHtml(vulnInfo.code_snippet)}</code></pre>
          </div>
        </div>
      `;
    }
    
    if (vulnInfo.trigger_point) {
      html += `
        <div class="card mb-3">
          <div class="card-header">
            <h5 class="mb-0"><i class="bi bi-bullseye me-2"></i>Trigger Point</h5>
          </div>
          <div class="card-body">
            <pre><code class="language-javascript">${escapeHtml(vulnInfo.trigger_point)}</code></pre>
          </div>
        </div>
      `;
    }
  }
  
  if (retrievedRootcauses.length > 0) {
    html += `
      <div class="card">
        <div class="card-header">
          <h5 class="mb-0"><i class="bi bi-list-check me-2"></i>Matched Root Cause Entries (${retrievedRootcauses.length})</h5>
        </div>
        <div class="card-body">
          <ul class="list-group">
    `;
    
    retrievedRootcauses.forEach(entry => {
      let name = 'Unknown Entry';
      if (typeof entry === 'string') {
        const nameMatch = entry.match(/Name: (.+?)(?:\n|$)/);
        name = nameMatch ? nameMatch[1] : entry.substring(0, 50);
      } else {
        name = entry.name || 'Unknown';
      }
      html += `<li class="list-group-item">${name}</li>`;
    });
    
    html += `
          </ul>
        </div>
      </div>
    `;
  }
  
  if (!html) {
    html = '<div class="alert alert-warning">No root cause analysis data available</div>';
  }
  
  rootcauseContent.innerHTML = html;
  rootcauseBadge.textContent = vulnInfo.vulnerability_name ? 1 : 0;
  
  // Highlight code
  setTimeout(() => {
    document.querySelectorAll('pre code').forEach((block) => {
      if (window.hljs) {
        hljs.highlightElement(block);
      }
    });
  }, 100);
}

// Display exploit analysis
// Display exploit analysis
function displayExploitAnalysis(exploitAnalysis) {
  const exploitContent = document.getElementById('exploitContent');
  const exploitBadge = document.getElementById('exploitBadge');
  
  if (!exploitContent) return;

  // 直接从后端返回的数据结构中获取数据
  const stepSelection = exploitAnalysis?.step_selection || {};
  const selectedSteps = stepSelection.selected_steps || [];
  const detailedSteps = exploitAnalysis?.retrieved_detailed_steps || [];
  const pocCode = exploitAnalysis?.poc_generation || '';
  
  let html = '';

  // 1. 显示攻击摘要（如果有）
  if (stepSelection.exploit_summary) {
    html += `
      <div class="card mb-3">
        <div class="card-header bg-warning">
          <h5 class="mb-0"><i class="bi bi-shield-exclamation me-2"></i>Attack Summary</h5>
        </div>
        <div class="card-body">
          <p>${escapeHtml(stepSelection.exploit_summary)}</p>
        </div>
      </div>
    `;
  }

  // 2. 显示选定的攻击步骤
  if (selectedSteps.length > 0) {
    html += `
      <div class="card mb-3">
        <div class="card-header">
          <h5 class="mb-0"><i class="bi bi-list-steps me-2"></i>Attack Steps (${selectedSteps.length})</h5>
        </div>
        <div class="card-body">
          <ol class="list-group list-group-numbered">
    `;
    
    selectedSteps.forEach(step => {
      html += `<li class="list-group-item">${escapeHtml(step)}</li>`;
    });
    
    html += `
          </ol>
        </div>
      </div>
    `;
  }

  // 3. 显示详细步骤（如果有）
  if (detailedSteps.length > 0) {
    html += `
      <div class="card mb-3">
        <div class="card-header">
          <h5 class="mb-0"><i class="bi bi-info-circle me-2"></i>Detailed Steps</h5>
        </div>
        <div class="card-body">
    `;
    
    detailedSteps.forEach((step, index) => {
      // 如果 detailedSteps 是字符串，直接显示
      if (typeof step === 'string') {
        html += `
          <div class="border rounded p-3 mb-3">
            <pre class="mb-0" style="white-space: pre-wrap;">${escapeHtml(step)}</pre>
          </div>
        `;
      } 
      // 如果是对象，格式化显示
      else if (typeof step === 'object' && step !== null) {
        html += `
          <div class="border rounded p-3 mb-3">
            <h6 class="fw-bold">Step ${index + 1}</h6>
            <p><strong>Description:</strong> ${escapeHtml(step.description || '')}</p>
            <p><strong>Impact:</strong> ${escapeHtml(step.impact || '')}</p>
          </div>
        `;
      }
    });
    
    html += `
        </div>
      </div>
    `;
  }

  // 4. 显示 POC 代码
  if (pocCode) {
    html += `
      <div class="card mt-3 border-success">
        <div class="card-header bg-success text-white">
          <i class="bi bi-code-slash me-2"></i>Proof of Concept (POC)
        </div>
        <div class="card-body">
          <pre><code class="language-javascript">${escapeHtml(pocCode)}</code></pre>
        </div>
      </div>
    `;
  }

  // 5. 如果没有数据，显示提示
  if (!html) {
    html = '<div class="alert alert-info">No exploit analysis data available</div>';
  }

  // 渲染内容
  exploitContent.innerHTML = html;
  
  // 更新徽章
  if (exploitBadge) {
    exploitBadge.textContent = selectedSteps.length;
  }

  // 高亮代码
  setTimeout(() => {
    document.querySelectorAll('#exploitContent pre code').forEach((block) => {
      if (window.hljs) {
        try {
          hljs.highlightElement(block);
        } catch (e) {
          console.debug('Code highlighting skipped:', e.message);
        }
      }
    });
  }, 100);
}
/**
 * 渲染攻击步骤内容
 */
function renderExploitContent(validation) {
  const { steps, pocCode, errors, warnings } = validation;
  
  // 显示警告/错误（仅开发环境）
  const devNotes = process.env.NODE_ENV === 'development' ? `
    <div class="small text-muted mb-2">
      ${errors.map(e => `<div class="text-danger">⚠️ ${e}</div>`).join('')}
      ${warnings.map(w => `<div class="text-warning">⚠️ ${w}</div>`).join('')}
    </div>
  ` : '';

  if (steps.length === 0) {
    return `
      ${devNotes}
      <div class="alert alert-info">
        <i class="bi bi-info-circle me-2"></i>
        No exploit steps available
      </div>
    `;
  }

  let html = `
    ${devNotes}
    <div class="attack-steps-container">
      <div class="mb-3">
        <span class="badge bg-primary">Total Steps: ${steps.length}</span>
      </div>
  `;

  // 渲染每个步骤
  steps.forEach((step, index) => {
    html += renderAttackStep(step, index);
  });

  // 渲染 POC 代码
  if (pocCode) {
    html += renderPOCCode(pocCode);
  }

  html += '</div>';
  return html;
}

/**
 * 渲染单个攻击步骤
 */
function renderAttackStep(step, index) {
  return `
    <div class="card mb-3 step-card" data-step-index="${index}">
      <div class="card-header bg-light d-flex justify-content-between align-items-center">
        <h6 class="mb-0 fw-bold">
          <span class="step-number">${index + 1}</span>
          ${escapeHtml(step.step_name)}
        </h6>
        <span class="badge ${getCategoryBadgeClass(step.category)}">
          ${escapeHtml(step.category)}
        </span>
      </div>
      
      <div class="card-body">
        <div class="mb-3">
          <strong>Impact:</strong>
          <p class="mt-1">${escapeHtml(step.impact)}</p>
        </div>
        
        ${renderListSection('Execution Steps', step.execution_steps, 'ol')}
        ${renderListSection('Sample Code', step.sample_code, 'pre')}
        
        <div class="mt-2 text-muted small">
          <i class="bi bi-clock"></i> Validated: ${step._meta?.timestamp || 'N/A'}
        </div>
      </div>
    </div>
  `;
}

/**
 * 渲染列表部分
 */
function renderListSection(title, items, type = 'ol') {
  if (!items || items.length === 0) return '';

  if (type === 'pre') {
    return `
      <div class="mt-3">
        <strong>${title}:</strong>
        <pre class="mt-2 bg-light p-2 rounded"><code class="language-javascript">${escapeHtml(items.join('\n'))}</code></pre>
      </div>
    `;
  }

  return `
    <div class="mt-3">
      <strong>${title}:</strong>
      <${type} class="mt-1">
        ${items.map(item => `<li>${escapeHtml(item)}</li>`).join('')}
      </${type}>
    </div>
  `;
}

/**
 * 渲染 POC 代码
 */
function renderPOCCode(code) {
  return `
    <div class="card mt-3 border-success">
      <div class="card-header bg-success text-white">
        <i class="bi bi-code-slash me-2"></i>Proof of Concept (POC)
      </div>
      <div class="card-body">
        <pre><code class="language-javascript">${escapeHtml(code)}</code></pre>
      </div>
    </div>
  `;
}

/**
 * 根据分类获取徽章样式
 */
function getCategoryBadgeClass(category) {
  const categoryMap = {
    'SQL Injection': 'bg-danger',
    'XSS': 'bg-warning text-dark',
    'RCE': 'bg-dark',
    'Privilege Escalation': 'bg-purple',
    'Information Disclosure': 'bg-info'
  };
  
  return categoryMap[category] || 'bg-secondary';
}

/**
 * 高亮代码块
 */
function highlightCode() {
  setTimeout(() => {
    document.querySelectorAll('#exploitContent pre code').forEach((block) => {
      if (window.hljs) {
        try {
          hljs.highlightElement(block);
        } catch (e) {
          console.debug('Code highlighting skipped:', e.message);
        }
      }
    });
  }, 100);
}
// ========== Helper Functions ==========

/**
 * Extract field value from text
 * @param {string} text - Text to parse
 * @param {string} fieldName - Field name (e.g., 'Step Name')
 * @param {boolean} multiline - Whether to support multiline
 * @returns {string} Extracted field value
 */
function extractField(text, fieldName, multiline = false) {
  if (!text || !fieldName) return '';
  
  try {
    // Support Chinese bracket format: 【field name】
    const patterns = [
      `【${fieldName}】:\\s*(.+?)(?=\n【|$|\n\n)`,  // Chinese bracket format
      `${fieldName}:\\s*(.+?)(?=\n\\w|$|\n\n)`,    // English colon format
      `"${fieldName}":\\s*"(.+?)"`,                // JSON format
      `"${fieldName}":\\s*(.+?)(?=,|\n|})`         // JSON format without quotes
    ];
    
    for (const pattern of patterns) {
      const regex = new RegExp(pattern, multiline ? 's' : '');
      const match = text.match(regex);
      if (match && match[1]) {
        return match[1].trim();
      }
    }
  } catch (e) {
    console.warn(`Failed to extract field ${fieldName}:`, e);
  }
  
  return '';
}

/**
 * Parse array from string
 * @param {string} str - String containing array, e.g., "['a', 'b', 'c']" or '["a", "b", "c"]'
 * @returns {Array} Parsed array
 */
function parseArrayFromString(str) {
  if (!str) return [];
  
  // If already array, return directly
  if (Array.isArray(str)) return str;
  
  // Ensure it's a string
  const strValue = String(str).trim();
  if (!strValue) return [];
  
  try {
    // Try direct JSON parsing (handle double quote format)
    if (strValue.startsWith('[') && strValue.endsWith(']')) {
      // Try replacing single quotes with double quotes
      const jsonCompatible = strValue.replace(/'/g, '"');
      return JSON.parse(jsonCompatible);
    }
  } catch (e) {
    console.warn('JSON parsing failed, attempting manual parse:', e.message);
  }
  
  // Manual parse for single quote arrays
  try {
    // Match content inside brackets
    const match = strValue.match(/\[(.*)\]/s);
    if (match) {
      const content = match[1].trim();
      if (!content) return [];
      
      const items = [];
      let current = '';
      let inQuote = false;
      let quoteChar = '';
      
      for (let i = 0; i < content.length; i++) {
        const char = content[i];
        
        // Handle quotes
        if ((char === '"' || char === "'") && (i === 0 || content[i-1] !== '\\')) {
          if (!inQuote) {
            inQuote = true;
            quoteChar = char;
          } else if (char === quoteChar) {
            inQuote = false;
          }
          continue; // Don't add quote characters
        }
        
        // Handle comma separation
        if (char === ',' && !inQuote) {
          if (current.trim()) {
            items.push(current.trim());
          }
          current = '';
        } else {
          current += char;
        }
      }
      
      // Add last item
      if (current.trim()) {
        items.push(current.trim());
      }
      
      return items;
    }
  } catch (e) {
    console.warn('Manual array parsing failed:', e);
  }
  
  // If all else fails, split by lines as fallback
  return strValue.split('\n')
    .map(line => line.trim())
    .filter(line => line && !line.startsWith('[') && !line.endsWith(']'))
    .map(line => line.replace(/^['"]|['"]$/g, '')); // Remove quotes
}

// Display POC reachability verification
function displayPOCVerification(pocVerification) {
  const pocContent = document.getElementById('pocContent');
  const pocBadge = document.getElementById('pocBadge');
  
  if (!pocContent) return;
  
  const isTriggered = pocVerification.vulnerability_triggered || false;
  const reasoning = pocVerification.reasoning_summary || 'No summary';
  const executionTrace = pocVerification.execution_trace || [];
  const recommendations = pocVerification.recommendations || [];
  
  let html = `
    <div class="card mb-3">
      <div class="card-header bg-${isTriggered ? 'success' : 'danger'} text-white">
        <h5 class="mb-0"><i class="bi bi-${isTriggered ? 'check-circle' : 'exclamation-circle'} me-2"></i>Verification Result</h5>
      </div>
      <div class="card-body">
        <div class="alert alert-${isTriggered ? 'success' : 'danger'}">
          <h5>${isTriggered ? '✅ Verification Passed' : '❌ Verification Failed'}</h5>
          <p>POC ${isTriggered ? 'can' : 'cannot'} successfully trigger the vulnerability</p>
        </div>
      </div>
    </div>
    
    <div class="card mb-3">
      <div class="card-header">
        <h5 class="mb-0"><i class="bi bi-chat-text me-2"></i>Reasoning Summary</h5>
      </div>
      <div class="card-body">
        <p>${reasoning}</p>
      </div>
    </div>
  `;
  
  if (executionTrace.length > 0) {
    html += `
      <div class="card mb-3">
        <div class="card-header">
          <h5 class="mb-0"><i class="bi bi-list-ul me-2"></i>Execution Trace (${executionTrace.length})</h5>
        </div>
        <div class="card-body">
          <ul class="list-group">
    `;
    
    executionTrace.forEach((step, index) => {
      const operation = step.operation || step.function || 'Unknown';
      const params = step.parameters || step.state_change || '';
      html += `<li class="list-group-item">Step ${index + 1}: ${operation} → ${params}</li>`;
    });
    
    html += `
          </ul>
        </div>
      </div>
    `;
  }
  
  if (recommendations.length > 0) {
    html += `
      <div class="card">
        <div class="card-header">
          <h5 class="mb-0"><i class="bi bi-lightbulb me-2"></i>Recommendations</h5>
        </div>
        <div class="card-body">
          <ul class="list-group">
    `;
    
    recommendations.forEach((rec, index) => {
      html += `<li class="list-group-item">${index + 1}. ${rec}</li>`;
    });
    
    html += `
          </ul>
        </div>
      </div>
    `;
  }
  
  pocContent.innerHTML = html;
  pocBadge.textContent = executionTrace.length;
}

// Node color configuration
function getNodeColor(type) {
  const colors = {
    'nodejs_root': '#4c78a8',
    'nodejs_type': '#54a24b',
    'rootcause': '#e45756',
    'exploit': '#f58518',
    'complex': '#e377c2',
    'default': '#bab0ac'
  };
  return colors[type] || colors['default'];
}

function getTypeLabel(type) {
  const labels = {
    'nodejs_root': 'Root Node',
    'nodejs_type': 'Component',
    'rootcause': 'Root Cause',
    'exploit': 'Exploit',
    'complex': 'Complex',
    'default': 'Unknown'
  };
  return labels[type] || labels['default'];
}

// Render graph structure
function renderAnalysisGraph(graphData) {
  console.log('Starting graph rendering', graphData);
  
  const container = document.querySelector('.graph-container');
  const placeholder = document.getElementById('graphPlaceholder');
  const svgContainer = document.getElementById('graphSvgContainer');
  
  if (!container || !svgContainer) {
    console.log('Container does not exist');
    return;
  }
  
  if (!graphData || !graphData.visualization_data) {
    if (placeholder) {
      placeholder.innerHTML = `
        <div class="text-center text-danger">
          <i class="bi bi-exclamation-triangle" style="font-size: 3rem;"></i>
          <p class="mt-2">Graph data does not exist</p>
        </div>
      `;
      placeholder.style.display = 'flex';
    }
    return;
  }
  
  const nodes = graphData.visualization_data.nodes || [];
  const links = graphData.visualization_data.edges || [];
  
  console.log('Nodes:', nodes.length, 'Edges:', links.length);
  
  if (nodes.length === 0) {
    if (placeholder) {
      placeholder.innerHTML = `
        <div class="text-center text-warning">
          <i class="bi bi-exclamation-circle" style="font-size: 3rem;"></i>
          <p class="mt-2">No nodes in graph</p>
        </div>
      `;
      placeholder.style.display = 'flex';
    }
    return;
  }
  
  // Hide placeholder, clear container
  if (placeholder) placeholder.style.display = 'none';
  svgContainer.innerHTML = '';
  
  const width = container.clientWidth || 800;
  const height = container.clientHeight || 500;
  console.log('Canvas size:', width, 'x', height);
  
  // Set initial random positions for each node
  nodes.forEach((node) => {
    node.x = Math.random() * width;
    node.y = Math.random() * height;
  });
  
  // Create SVG
  const svg = d3.select("#graphSvgContainer")
    .append("svg")
    .attr("width", width)
    .attr("height", height)
    .style("background-color", "#f8fafc");
  
  // Create group for zooming
  const g = svg.append("g");
  
  // Create zoom behavior
  const zoom = d3.zoom()
    .scaleExtent([0.1, 4])
    .on("zoom", (event) => {
      g.attr("transform", event.transform);
    });
  
  svg.call(zoom);
  
  // Create force-directed graph
  const simulation = d3.forceSimulation(nodes)
    .force("link", d3.forceLink(links).id(d => d.id)
      .distance(100)
      .strength(0.3))
    .force("charge", d3.forceManyBody()
      .strength(-200)
      .theta(0.8))
    .force("collision", d3.forceCollide()
      .radius(50)
      .strength(0.7))
    .alpha(1)
    .alphaDecay(0.02)
    .velocityDecay(0.3);

  // Draw links
  const link = g.append("g")
    .selectAll("line")
    .data(links)
    .enter()
    .append("line")
    .attr("class", "link")
    .attr("stroke", "#94a3b8")
    .attr("stroke-width", 1.8)
    .attr("stroke-opacity", 0.6);
  
  // Draw nodes
  const node = g.append("g")
    .selectAll("g")
    .data(nodes)
    .enter()
    .append("g")
    .attr("class", "node")
    .call(d3.drag()
      .on("start", dragstarted)
      .on("drag", dragged)
      .on("end", dragended));
  
  // Add circles
  node.append("circle")
    .attr("r", 25)
    .attr("fill", d => getNodeColor(d.type))
    .attr("stroke", "#2d3748")
    .attr("stroke-width", 1.8)
    .attr("stroke-opacity", 0.8);
  
  // Add node names
  node.append("text")
    .attr("class", "name")
    .attr("dy", -5)
    .attr("text-anchor", "middle")
    .attr("fill", "#fff")
    .style("font-size", "10px")
    .style("font-weight", "600")
    .text(d => {
      const name = d.name || 'Unknown';
      return name.length > 12 ? name.substring(0, 10) + '...' : name;
    });
  
  // Add node type labels
  node.append("text")
    .attr("class", "type")
    .attr("dy", 15)
    .attr("text-anchor", "middle")
    .attr("fill", "rgba(255,255,255,0.9)")
    .style("font-size", "8px")
    .text(d => getTypeLabel(d.type));
  
  // Tooltip
  const tooltip = d3.select("body")
    .append("div")
    .attr("class", "tooltip")
    .style("opacity", 0);
  
  // Mouse interactions
  node.on("mouseover", function(event, d) {
    d3.select(this).select("circle")
      .attr("stroke", "#ffcc00")
      .attr("stroke-width", 2.5);
    
    link.attr("stroke", l => 
      (l.source.id === d.id || l.target.id === d.id) ? "#ffcc00" : "#94a3b8"
    )
    .attr("stroke-width", l => 
      (l.source.id === d.id || l.target.id === d.id) ? 2.5 : 1.8
    );
    
    tooltip.transition()
      .duration(200)
      .style("opacity", .95);
    
    tooltip.html(`
      <div style="font-weight:600;margin-bottom:5px">${d.name}</div>
      <div><strong>Type:</strong> ${getTypeLabel(d.type)}</div>
      <div style="margin-top:8px">${d.description || 'No detailed description'}</div>
    `)
      .style("left", (event.pageX + 15) + "px")
      .style("top", (event.pageY - 28) + "px");
  })
  .on("mouseout", function() {
    d3.select(this).select("circle")
      .attr("stroke", "#2d3748")
      .attr("stroke-width", 1.8);
    
    link.attr("stroke", "#94a3b8")
        .attr("stroke-width", 1.8);
    
    tooltip.transition()
      .duration(300)
      .style("opacity", 0);
  });
  
  // Update positions
  simulation.on("tick", () => {
    link
      .attr("x1", d => d.source.x)
      .attr("y1", d => d.source.y)
      .attr("x2", d => d.target.x)
      .attr("y2", d => d.target.y);
    
    node.attr("transform", d => `translate(${d.x},${d.y})`);
  });
  
  // Save to global variables
  window.graphSimulation = simulation;
  window.graphSvg = svg;
  window.graphG = g;
  window.graphZoom = zoom;
  
  // ========== Add window resize adaptation ==========
  function handleResize() {
    const newWidth = container.clientWidth;
    const newHeight = container.clientHeight;
    
    if (newWidth > 0 && newHeight > 0) {
      console.log('Window resized, adapting:', newWidth, 'x', newHeight);
      
      // Update SVG dimensions
      svg.attr("width", newWidth).attr("height", newHeight);
      
      // Update force graph center
      simulation.force("center", d3.forceCenter(newWidth / 2, newHeight / 2));
      
      // Restart simulation to adapt to new dimensions
      simulation.alpha(0.3).restart();
    }
  }
  
  // Add resize listener
  window.addEventListener('resize', handleResize);
  
  // Force restart simulation
  simulation.alpha(1).restart();
  
  // Auto-center
  setTimeout(() => {
    if (nodes.length > 0) {
      const centerX = d3.mean(nodes, d => d.x) || width / 2;
      const centerY = d3.mean(nodes, d => d.y) || height / 2;
      
      svg.transition()
        .duration(750)
        .call(
          zoom.transform,
          d3.zoomIdentity.translate(width / 2 - centerX, height / 2 - centerY)
        );
    }
  }, 1000);
  
  // Drag functions
  function dragstarted(event) {
    if (!event.active) simulation.alphaTarget(0.3).restart();
    event.subject.fx = event.subject.x;
    event.subject.fy = event.subject.y;
  }
  
  function dragged(event) {
    event.subject.fx = event.x;
    event.subject.fy = event.y;
  }
  
  function dragended(event) {
    if (!event.active) simulation.alphaTarget(0);
    event.subject.fx = null;
    event.subject.fy = null;
  }
  
  // Return cleanup function (optional)
  return () => {
    window.removeEventListener('resize', handleResize);
  };
}

// Zoom controls
window.zoomIn = function() {
  if (window.graphSvg && window.graphZoom) {
    window.graphSvg.transition().duration(300).call(window.graphZoom.scaleBy, 1.5);
  }
};

window.zoomOut = function() {
  if (window.graphSvg && window.graphZoom) {
    window.graphSvg.transition().duration(300).call(window.graphZoom.scaleBy, 0.75);
  }
};

window.resetZoom = function() {
  if (window.graphSvg && window.graphZoom) {
    window.graphSvg.transition().duration(300).call(window.graphZoom.transform, d3.zoomIdentity);
  }
};

// Download handlers
function downloadReportHandler() {
  if (currentResult && currentResult.result_dir) {
    window.open(`/results/${currentResult.result_dir}/security_report.md`, '_blank');
  }
}

function downloadPOCHandler() {
  if (currentResult && currentResult.result_dir) {
    window.open(`/results/${currentResult.result_dir}/exploit_poc.js`, '_blank');
  }
}

function downloadJsonHandler() {
  if (currentResult && currentResult.result_dir) {
    window.open(`/results/${currentResult.result_dir}/full_analysis.json`, '_blank');
  }
}

// HTML escape
function escapeHtml(text) {
  if (!text) return '';
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// Show notification
function showNotification(message, type = 'info') {
  const notification = document.createElement('div');
  notification.className = `notification-toast notification-${type}`;
  notification.innerHTML = `
    <i class="bi bi-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : 'info-circle'}"></i>
    <span>${message}</span>
  `;
  
  notification.style.cssText = `
    position: fixed;
    top: 20px;
    right: 20px;
    background: white;
    border-left: 4px solid ${type === 'success' ? '#198754' : type === 'error' ? '#dc3545' : '#0d6efd'};
    border-radius: 8px;
    padding: 12px 20px;
    box-shadow: 0 4px 12px rgba(0,0,0,0.15);
    z-index: 9999;
    display: flex;
    align-items: center;
    gap: 12px;
    animation: slideIn 0.3s ease;
  `;
  
  document.body.appendChild(notification);
  
  setTimeout(() => {
    notification.style.animation = 'slideOut 0.3s ease';
    setTimeout(() => {
      document.body.removeChild(notification);
    }, 300);
  }, 3000);
}
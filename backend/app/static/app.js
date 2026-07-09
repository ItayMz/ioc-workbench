const LABELS = new Set([
  'url',
  'domain',
  'ip',
  'ipaddress',
  'address',
  'ioc',
  'indicators',
  'indicator',
]);

const SEPARATORS = new Set([',', ';', ':', '|', '(', ')', '[', ']', '{', '}']);
const MAX_LINE_LENGTH = 8192;
const REFANG_PATTERNS = {
  'hxxps[://]': 'https://',
  'hxxp[://]': 'http://',
  'hxxps[:]//': 'https://',
  'hxxp[:]//': 'http://',
  'hxxps://': 'https://',
  'hxxp://': 'http://',
  'https[:]//': 'https://',
  'http[:]//': 'http://',
  '[.]': '.',
  '(.)': '.',
  '{.}': '.',
  '[dot]': '.',
  '(dot)': '.',
  ' dot ': '.',
  '[:]': ':',
  '[@]': '@',
  '(at)': '@',
  '[at]': '@',
};

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function refang(value) {
  let cleaned = String(value || '').trim().replace(/^['"]|['"]$/g, '');

  for (const [oldValue, newValue] of Object.entries(REFANG_PATTERNS)) {
    cleaned = cleaned.split(oldValue).join(newValue);
  }

  cleaned = cleaned.replace(/\\\./g, '.');
  cleaned = cleaned.replace(/\s+/g, '');
  return cleaned;
}

function isIPv4(value) {
  return /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/.test(value);
}

function isIPv6(value) {
  return /^(?:[0-9A-Fa-f]{1,4}:){1,7}[0-9A-Fa-f]{1,4}$/.test(value) || /^(?:[0-9A-Fa-f]{1,4}:){1,7}:$/.test(value) || /^::1$/.test(value);
}

function extractCandidates(rawText) {
  if (!rawText || typeof rawText !== 'string') {
    return [];
  }

  const candidateTokens = [];
  const lines = rawText.split(/\r?\n/);

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line) {
      continue;
    }

    let cleaned = line.replace(/(?i)\b(?:url|domain|ip|address|ioc|indicators?|indicator)\b\s*[-:]+\s*/g, '');
    cleaned = cleaned.replace(/(?i)\b(?:url|domain|ip|address|ioc|indicators?|indicator)\b/g, '');

    for (const token of cleaned.split(/[\s,;|]+/)) {
      const normalizedToken = token.trim("()[]{}:;,'\"");
      if (!normalizedToken) {
        continue;
      }

      if (LABELS.has(normalizedToken.toLowerCase())) {
        continue;
      }

      if (SEPARATORS.has(normalizedToken)) {
        continue;
      }

      candidateTokens.push(normalizedToken);
    }
  }

  return candidateTokens;
}

function classifyIndicator(value) {
  const originalValue = value == null ? '' : String(value);
  const cleanedValue = originalValue.trim();
  const refangedValue = refang(cleanedValue);

  if (!cleanedValue) {
    return {
      original_value: originalValue,
      refanged_value: refangedValue,
      valid: false,
      reason: 'empty_value',
    };
  }

  if (cleanedValue.length > MAX_LINE_LENGTH) {
    return {
      original_value: originalValue,
      refanged_value: refangedValue,
      valid: false,
      reason: 'line_too_long',
    };
  }

  let indicatorType = null;
  if (/^[0-9a-fA-F]{32}$/.test(refangedValue)) {
    indicatorType = 'FileMd5';
  } else if (/^[0-9a-fA-F]{40}$/.test(refangedValue)) {
    indicatorType = 'FileSha1';
  } else if (/^[0-9a-fA-F]{64}$/.test(refangedValue)) {
    indicatorType = 'FileSha256';
  } else if (isIPv4(refangedValue) || isIPv6(refangedValue)) {
    indicatorType = 'IpAddress';
  } else if (/^https?:\/\/.test(refangedValue)) {
    indicatorType = 'Url';
  } else if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(refangedValue)) {
    indicatorType = 'SenderEmailAddress';
  } else if (/^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/.test(refangedValue)) {
    indicatorType = 'DomainName';
  }

  const valid = Boolean(indicatorType);
  return {
    original_value: originalValue,
    refanged_value: refangedValue,
    indicator_type: indicatorType,
    action: valid ? (indicatorType === 'FileMd5' || indicatorType === 'FileSha1' || indicatorType === 'FileSha256' ? 'BlockAndRemediate' : 'Block') : null,
    category: valid ? 'Malware' : null,
    generate_alert: valid ? true : null,
    severity: valid ? 'High' : null,
    expiration_time: valid ? '2099-12-31T23:59:59.0Z' : null,
    valid,
    reason: valid ? null : 'unsupported_indicator',
  };
}

function deduplicateIndicators(indicators) {
  const seen = new Set();
  const deduplicated = [];

  for (const indicator of indicators) {
    const key = `${indicator.indicator_type || 'None'}::${String(indicator.refanged_value || '').toLowerCase()}`;
    if (seen.has(key)) {
      continue;
    }

    seen.add(key);
    deduplicated.push(indicator);
  }

  return deduplicated;
}

function buildProcessingSummary(indicators, groupedIocs, kqlQueries) {
  return {
    processed: indicators.length,
    md5: groupedIocs.md5.length,
    sha1: groupedIocs.sha1.length,
    sha256: groupedIocs.sha256.length,
    ipv4: groupedIocs.ipv4.length,
    ipv6: groupedIocs.ipv6.length,
    domains: groupedIocs.domains.length,
    urls: groupedIocs.urls.length,
    duplicatesRemoved: 0,
    queriesGenerated: Object.values(kqlQueries).filter(Boolean).length,
  };
}

function groupIocsByType(indicators) {
  return {
    md5: [],
    sha1: [],
    sha256: [],
    ipv4: [],
    ipv6: [],
    domains: [],
    urls: [],
  };
}

function buildKqlQueries(groupedIocs, lookbackDays) {
  const normalizedLookback = normalizeLookback(lookbackDays);
  const queries = {
    md5: buildKqlQuery('md5', groupedIocs.md5, 'DeviceFileEvents', 'MD5', 'IOC_MD5', normalizedLookback),
    sha1: buildKqlQuery('sha1', groupedIocs.sha1, 'DeviceFileEvents', 'SHA1', 'IOC_SHA1', normalizedLookback),
    sha256: buildKqlQuery('sha256', groupedIocs.sha256, 'DeviceFileEvents', 'SHA256', 'IOC_SHA256', normalizedLookback),
    ipv4: buildKqlQuery('ipv4', groupedIocs.ipv4, 'DeviceNetworkEvents', 'RemoteIP', 'IOC_IPV4', normalizedLookback),
    ipv6: buildKqlQuery('ipv6', groupedIocs.ipv6, 'DeviceNetworkEvents', 'RemoteIP', 'IOC_IPV6', normalizedLookback),
    domains: buildKqlQuery('domains', groupedIocs.domains, 'DeviceDnsEvents', 'QueryName', 'IOC_DOMAINS', normalizedLookback),
    urls: buildKqlQuery('urls', groupedIocs.urls, 'DeviceNetworkEvents', 'RemoteUrl', 'IOC_URLS', normalizedLookback),
  };

  return queries;
}

function normalizeLookback(value) {
  const numericValue = Number(value);
  if ([7, 30, 90, 180, 365].includes(numericValue)) {
    return numericValue;
  }
  return 90;
}

function buildKqlQuery(key, indicators, tableName, fieldName, variableName, lookbackDays) {
  if (!indicators.length) {
    return null;
  }

  const values = indicators.map((indicator) => JSON.stringify(indicator.refanged_value));
  const dynamicList = `dynamic([${values.join(', ')}])`;
  let query = `let ${variableName} = ${dynamicList};\n${tableName}\n| where Timestamp >= ago(${lookbackDays}d)\n`;

  if (key === 'md5') {
    query += `| where MD5 in~ (${variableName})\n`;
  } else if (key === 'sha1') {
    query += `| where SHA1 in~ (${variableName})\n`;
  } else if (key === 'sha256') {
    query += `| where SHA256 in~ (${variableName})\n`;
  } else if (key === 'ipv4' || key === 'ipv6') {
    query += `| where ${fieldName} in~ (${variableName})\n`;
  } else if (key === 'domains') {
    query += `| where ${fieldName} has_any (${variableName})\n`;
  } else if (key === 'urls') {
    query += `| where ${fieldName} in~ (${variableName})\n`;
  }

  query += '| project Timestamp, DeviceName, ActionType, ReportId';

  return {
    query,
    count: indicators.length,
    lookbackDays,
    tables: [tableName],
  };
}

function buildResponse(rawText, lookbackDays) {
  const candidateValues = extractCandidates(rawText);
  const indicators = deduplicateIndicators(candidateValues.map(classifyIndicator).filter(Boolean));
  const groupedIocs = groupIocsByType(indicators);

  for (const indicator of indicators) {
    if (!indicator.valid || !indicator.indicator_type) {
      continue;
    }

    if (indicator.indicator_type === 'FileMd5') {
      groupedIocs.md5.push(indicator);
    } else if (indicator.indicator_type === 'FileSha1') {
      groupedIocs.sha1.push(indicator);
    } else if (indicator.indicator_type === 'FileSha256') {
      groupedIocs.sha256.push(indicator);
    } else if (indicator.indicator_type === 'IpAddress') {
      const normalizedValue = String(indicator.refanged_value || '');
      if (isIPv4(normalizedValue)) {
        groupedIocs.ipv4.push(indicator);
      } else {
        groupedIocs.ipv6.push(indicator);
      }
    } else if (indicator.indicator_type === 'DomainName') {
      groupedIocs.domains.push(indicator);
    } else if (indicator.indicator_type === 'Url') {
      groupedIocs.urls.push(indicator);
    }
  }

  const kqlQueries = buildKqlQueries(groupedIocs, lookbackDays);
  const summary = buildProcessingSummary(indicators, groupedIocs, kqlQueries);
  summary.duplicatesRemoved = Math.max(0, candidateValues.length - indicators.length);

  return {
    indicators,
    total_count: indicators.length,
    valid_count: indicators.filter((indicator) => indicator.valid).length,
    invalid_count: indicators.filter((indicator) => !indicator.valid).length,
    counts_by_type: indicators.reduce((accumulator, indicator) => {
      if (!indicator.indicator_type) {
        return accumulator;
      }
      accumulator[indicator.indicator_type] = (accumulator[indicator.indicator_type] || 0) + 1;
      return accumulator;
    }, {}),
    title: 'Block Malicious Indicators',
    description: 'Indicators associated with a reported malicious campaign.',
    recommended_actions: 'Block the listed indicators and investigate any historical communication.',
    summary,
    kqlQueries,
  };
}

function parseText(rawText, lookbackDays) {
  return buildResponse(rawText, lookbackDays);
}

function exportCsv(data) {
  const headers = [
    'IndicatorType',
    'IndicatorValue',
    'ExpirationTime',
    'Action',
    'Severity',
    'Title',
    'Description',
    'RecommendedActions',
    'RbacGroups',
    'Category',
    'MitreTechniques',
    'GenerateAlert',
  ];

  const rows = data.indicators.filter((indicator) => indicator.valid).map((indicator) => [
    indicator.indicator_type || '',
    indicator.refanged_value || '',
    indicator.expiration_time || '',
    indicator.action || '',
    indicator.severity || '',
    data.title || '',
    data.description || '',
    data.recommended_actions || '',
    '',
    indicator.category || '',
    '',
    indicator.generate_alert ? 'True' : 'False',
  ]);

  const csvRows = [headers, ...rows].map((row) => row.map((value) => `"${String(value).replace(/"/g, '""')}"`).join(','));
  const csvContent = csvRows.join('\n');
  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = 'defender_iocs.csv';
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

function renderResults(data) {
  const result = document.getElementById('result');
  const queryEntries = Object.entries(data.kqlQueries || {}).filter(([, entry]) => Boolean(entry && entry.query));

  result.innerHTML = `
    <h2>Parsed Indicators</h2>
    <pre>${escapeHtml(JSON.stringify(data.indicators, null, 2))}</pre>
    <h2>Processing Summary</h2>
    <div class="meta-row">
      <span class="meta-chip"><span class="chip-label">Processed</span> <strong>${data.summary?.processed ?? 0}</strong></span>
      <span class="meta-chip"><span class="chip-label">MD5</span> <strong>${data.summary?.md5 ?? 0}</strong></span>
      <span class="meta-chip"><span class="chip-label">SHA1</span> <strong>${data.summary?.sha1 ?? 0}</strong></span>
      <span class="meta-chip"><span class="chip-label">SHA256</span> <strong>${data.summary?.sha256 ?? 0}</strong></span>
      <span class="meta-chip"><span class="chip-label">IPv4</span> <strong>${data.summary?.ipv4 ?? 0}</strong></span>
      <span class="meta-chip"><span class="chip-label">IPv6</span> <strong>${data.summary?.ipv6 ?? 0}</strong></span>
      <span class="meta-chip"><span class="chip-label">Domains</span> <strong>${data.summary?.domains ?? 0}</strong></span>
      <span class="meta-chip"><span class="chip-label">URLs</span> <strong>${data.summary?.urls ?? 0}</strong></span>
      <span class="meta-chip"><span class="chip-label">Duplicates removed</span> <strong>${data.summary?.duplicatesRemoved ?? 0}</strong></span>
      <span class="meta-chip"><span class="chip-label">Queries generated</span> <strong>${data.summary?.queriesGenerated ?? 0}</strong></span>
    </div>
    <h2>KQL Queries</h2>
    ${queryEntries.map(([key, entry]) => {
      const title = key === 'md5' ? 'MD5' : key === 'sha1' ? 'SHA1' : key === 'sha256' ? 'SHA256' : key === 'ipv4' ? 'IPv4' : key === 'ipv6' ? 'IPv6' : key === 'domains' ? 'Domains' : 'URLs';
      const count = entry.count;
      const tables = entry.tables || [];
      return `
        <div class="query-card">
          <div class="query-header">
            <h3 class="query-title">${escapeHtml(title)}</h3>
            <button type="button" onclick="copyQuery('${key}', ${JSON.stringify(entry.query)}, this)">Copy KQL</button>
          </div>
          <div class="meta-row">
            <span class="meta-chip"><span class="chip-label">IOC count</span> <strong>${count}</strong></span>
            <span class="meta-chip"><span class="chip-label">Lookback</span> <strong>Last ${entry.lookbackDays} days</strong></span>
            <span class="meta-chip tables">
              <span class="chip-label">Defender tables</span>
              <span class="table-list">${tables.map((table) => `<span class="table-pill">${escapeHtml(table)}</span>`).join('')}</span>
            </span>
          </div>
          <pre>${escapeHtml(entry.query)}</pre>
        </div>
      `;
    }).join('')}
  `;
}

function showError(message) {
  const result = document.getElementById('result');
  result.innerHTML = `<div class="notification" style="color: #b91c1c;">${escapeHtml(message)}</div>`;
}

function submitParse() {
  const rawText = document.getElementById('rawText').value;
  const lookbackDays = document.getElementById('lookbackSelect').value;
  const data = parseText(rawText, Number(lookbackDays));
  renderResults(data);
}

async function copyQuery(key, query, button) {
  try {
    await navigator.clipboard.writeText(query);
    const notification = document.createElement('div');
    notification.className = 'notification';
    notification.textContent = 'KQL copied to clipboard.';
    if (button) {
      button.parentElement.appendChild(notification);
    }
  } catch (error) {
    showError('Clipboard access was blocked. Please copy the query manually.');
  }
}

async function handleFileUpload(event) {
  const file = event.target.files && event.target.files[0];
  if (!file) {
    return;
  }

  try {
    const text = await readUploadedFile(file);
    const textarea = document.getElementById('rawText');
    textarea.value = text;
    submitParse();
  } catch (error) {
    showError(error.message || 'Unable to read the uploaded file.');
  }
}

async function readUploadedFile(file) {
  const lowerName = file.name.toLowerCase();
  if (!lowerName.endsWith('.csv') && !lowerName.endsWith('.txt')) {
    throw new Error('Unsupported file type. Please upload a .csv or .txt file.');
  }

  const bytes = await file.arrayBuffer();
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch (error) {
    throw new Error('The uploaded file could not be decoded as UTF-8.');
  }

  if (!text.trim()) {
    throw new Error('The uploaded file is empty.');
  }

  const rows = [];
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim()) {
      continue;
    }
    const columns = line.split(',');
    if (columns.length !== 1) {
      throw new Error('Malformed CSV file. Please provide one IOC per line.');
    }
    rows.push(columns[0].trim());
  }

  if (!rows.length) {
    throw new Error('The uploaded file is empty.');
  }

  return rows.join('\n');
}

window.submitParse = submitParse;
window.copyQuery = copyQuery;
window.addEventListener('DOMContentLoaded', () => {
  document.getElementById('fileInput').addEventListener('change', handleFileUpload);
  submitParse();
});

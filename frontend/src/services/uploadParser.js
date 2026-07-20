import * as XLSX from 'xlsx'

function normalizeHeader(value) {
  return String(value || '').trim().toLowerCase()
}

const VALUE_COLUMN_CANDIDATES = [
  'value',
  'indicator',
  'ioc',
  'ioc_value',
  'indicator_value',
  'observable',
  'artifact',
]

const CATEGORY_COLUMN_CANDIDATES = [
  'category',
  'ioc category',
  'threat category',
  'attack category',
  'att&ck tactic',
  'mitre tactic',
]

const CATEGORY_ALIASES = {
  collection: 'Collection',
  commandandcontrol: 'CommandAndControl',
  'command and control': 'CommandAndControl',
  c2: 'CommandAndControl',
  credentialaccess: 'CredentialAccess',
  'credential access': 'CredentialAccess',
  defenseevasion: 'DefenseEvasion',
  'defense evasion': 'DefenseEvasion',
  discovery: 'Discovery',
  execution: 'Execution',
  exfiltration: 'Exfiltration',
  exploit: 'Exploit',
  initialaccess: 'InitialAccess',
  'initial access': 'InitialAccess',
  lateralmovement: 'LateralMovement',
  'lateral movement': 'LateralMovement',
  malware: 'Malware',
  persistence: 'Persistence',
  privilegeescalation: 'PrivilegeEscalation',
  'privilege escalation': 'PrivilegeEscalation',
  ransomware: 'Ransomware',
  suspicious: 'SuspiciousActivity',
  suspiciousactivity: 'SuspiciousActivity',
  'suspicious activity': 'SuspiciousActivity',
  unwantedsoftware: 'UnwantedSoftware',
  'unwanted software': 'UnwantedSoftware',
}

function splitCsvRows(text) {
  const rows = []
  let row = []
  let field = ''
  let inQuotes = false

  for (let index = 0; index < text.length; index += 1) {
    const char = text[index]

    if (char === '"') {
      const nextChar = text[index + 1]
      if (inQuotes && nextChar === '"') {
        field += '"'
        index += 1
      } else {
        inQuotes = !inQuotes
      }
      continue
    }

    if (!inQuotes && char === ',') {
      row.push(field)
      field = ''
      continue
    }

    if (!inQuotes && (char === '\n' || char === '\r')) {
      if (char === '\r' && text[index + 1] === '\n') {
        index += 1
      }
      row.push(field)
      rows.push(row)
      row = []
      field = ''
      continue
    }

    field += char
  }

  if (inQuotes) {
    throw new Error('Malformed CSV file. Please fix quoting and try again.')
  }

  row.push(field)
  if (row.length > 1 || row[0].trim()) {
    rows.push(row)
  }

  return rows
}

function findMostCommonValue(values) {
  if (!values.length) {
    return null
  }

  const counts = new Map()
  for (const value of values) {
    counts.set(value, (counts.get(value) || 0) + 1)
  }

  return [...counts.entries()]
    .sort((left, right) => {
      if (right[1] !== left[1]) {
        return right[1] - left[1]
      }
      return left[0].localeCompare(right[0])
    })[0][0]
}

function selectCategoryColumn(headers) {
  const exactIndex = headers.indexOf('category')
  if (exactIndex !== -1) {
    return exactIndex
  }

  for (const candidate of CATEGORY_COLUMN_CANDIDATES) {
    const index = headers.indexOf(candidate)
    if (index !== -1) {
      return index
    }
  }

  return -1
}

function normalizeCategory(value) {
  const normalized = String(value || '').trim().toLowerCase()
  if (!normalized) {
    return null
  }

  if (CATEGORY_ALIASES[normalized]) {
    return CATEGORY_ALIASES[normalized]
  }

  const compact = normalized.replace(/[_-]/g, ' ').replace(/\s+/g, ' ').trim()
  if (CATEGORY_ALIASES[compact]) {
    return CATEGORY_ALIASES[compact]
  }

  if (CATEGORY_ALIASES[compact.replace(/\s+/g, '')]) {
    return CATEGORY_ALIASES[compact.replace(/\s+/g, '')]
  }

  return null
}

function findValueColumnIndex(headers) {
  for (const candidate of VALUE_COLUMN_CANDIDATES) {
    const index = headers.indexOf(candidate)
    if (index !== -1) {
      return index
    }
  }

  return -1
}

function extractIocCandidatesFromText(value) {
  const text = String(value || '').trim()
  if (!text) {
    return []
  }

  const candidates = []
  const tokens = text
    .split(/[\s,;|]+/)
    .map((token) => token.trim().replace(/^[()[\]{}:;,'"]+|[()[\]{}:;,'"]+$/g, ''))
    .filter(Boolean)

  for (const token of tokens) {
    const lowered = token.toLowerCase()

    // Keep extraction conservative: only tokens that look IOC-like are forwarded.
    const looksLikeHash = /^[0-9a-fA-F]{32}$/.test(token)
      || /^[0-9a-fA-F]{40}$/.test(token)
      || /^[0-9a-fA-F]{64}$/.test(token)
    const looksLikeUrl = /^(?:https?|hxxps?|https\[:\]|http\[:\])[:/]/i.test(token)
    const looksLikeIp = /^(?:\d{1,3}|\d{1,3}\[\.\]\d{1,3})(?:\.|\[\.\])\d{1,3}(?:\.|\[\.\])\d{1,3}$/.test(token)
      || /:/.test(token)
    const looksLikeDomain = token.includes('.') || token.includes('[.]')
    const looksLikeEmail = /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(token)

    if (looksLikeEmail) {
      continue
    }

    if (looksLikeHash || looksLikeUrl || looksLikeIp || looksLikeDomain) {
      candidates.push(token)
      continue
    }

    if (lowered.includes('hxxp') || lowered.includes('http') || lowered.includes('[.]')) {
      candidates.push(token)
    }
  }

  return candidates
}

function parseRowsWithFallback(rows, sourceFile) {
  const iocs = []
  const seen = new Set()

  for (const row of rows || []) {
    for (const cell of row || []) {
      if (cell == null) {
        continue
      }

      for (const candidate of extractIocCandidatesFromText(cell)) {
        if (seen.has(candidate)) {
          continue
        }

        seen.add(candidate)
        iocs.push(candidate)
      }
    }
  }

  return {
    iocs,
    campaignCandidates: [],
    metadataEntries: iocs.map((value) => ({
      value,
      campaignName: null,
      category: null,
      sourceFile,
    })),
  }
}

function parseStructuredRows(rows, sourceFile, emptyMessage) {
  if (!rows.length) {
    throw new Error(emptyMessage)
  }

  const firstNonEmptyRow = rows.find((row) => row.some((cell) => String(cell || '').trim()))
  if (!firstNonEmptyRow) {
    throw new Error(emptyMessage)
  }

  const headers = firstNonEmptyRow.map(normalizeHeader)
  const valueIndex = findValueColumnIndex(headers)
  const eventInfoIndex = headers.indexOf('event_info')
  const categoryIndex = selectCategoryColumn(headers)

  if (valueIndex === -1) {
    return parseRowsWithFallback(rows, sourceFile)
  }

  const iocs = []
  const campaignCandidates = []
  const metadataEntries = []

  const startIndex = rows.indexOf(firstNonEmptyRow) + 1
  for (const row of rows.slice(startIndex)) {
    const iocValue = String(row[valueIndex] || '').trim()
    if (iocValue) {
      iocs.push(iocValue)
    }

    if (eventInfoIndex !== -1) {
      const eventInfoValue = String(row[eventInfoIndex] || '').trim()
      if (eventInfoValue) {
        campaignCandidates.push(eventInfoValue)
      }

      metadataEntries.push({
        value: iocValue,
        campaignName: eventInfoValue || null,
        category: categoryIndex !== -1 ? normalizeCategory(row[categoryIndex]) : null,
        sourceFile,
      })
      continue
    }

    metadataEntries.push({
      value: iocValue,
      campaignName: null,
      category: categoryIndex !== -1 ? normalizeCategory(row[categoryIndex]) : null,
      sourceFile,
    })
  }

  return {
    iocs,
    campaignCandidates,
    metadataEntries,
  }
}

function parseCsvContent(text, sourceFile) {
  const rows = splitCsvRows(text)
  return parseStructuredRows(rows, sourceFile, 'Uploaded CSV is empty.')
}

function parseXlsxContent(buffer, sourceFile) {
  let workbook

  try {
    workbook = XLSX.read(buffer, { type: 'array' })
  } catch {
    throw new Error('The uploaded XLSX file is corrupted or invalid.')
  }

  const sheetNames = workbook?.SheetNames || []
  if (!sheetNames.length) {
    throw new Error('The uploaded file is empty.')
  }

  const combined = {
    iocs: [],
    campaignCandidates: [],
    metadataEntries: [],
  }

  let hasTabularData = false
  for (const sheetName of sheetNames) {
    const worksheet = workbook.Sheets[sheetName]
    if (!worksheet) {
      continue
    }

    const rows = XLSX.utils.sheet_to_json(worksheet, { header: 1, defval: '' })
    const hasContent = rows.some((row) => row.some((cell) => String(cell || '').trim()))
    if (!hasContent) {
      continue
    }

    hasTabularData = true
    const parsed = parseStructuredRows(rows, sourceFile, 'Uploaded XLSX is empty.')
    combined.iocs.push(...parsed.iocs)
    combined.campaignCandidates.push(...parsed.campaignCandidates)
    combined.metadataEntries.push(...parsed.metadataEntries)
  }

  if (!hasTabularData) {
    throw new Error('The uploaded file is empty.')
  }

  return combined
}

function parseTxtContent(text, sourceFile) {
  const normalizedLines = text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)

  return {
    iocs: normalizedLines,
    campaignCandidates: [],
    metadataEntries: normalizedLines.map((value) => ({
      value,
      campaignName: null,
      category: null,
      sourceFile,
    })),
  }
}

export function resolveCampaignName(manualCampaignName, detectedCampaignName) {
  const manual = String(manualCampaignName || '').trim()
  if (manual) {
    return manual
  }

  const detected = String(detectedCampaignName || '').trim()
  return detected || null
}

export async function parseUploadedFiles(files) {
  const uploadedFiles = Array.from(files || [])
  if (!uploadedFiles.length) {
    throw new Error('No files selected.')
  }

  const combinedIocs = []
  const campaignCandidates = []
  const metadataEntries = []
  const unsupportedFiles = []

  for (const file of uploadedFiles) {
    const fileName = String(file?.name || '').toLowerCase()

    if (fileName.endsWith('.csv')) {
      const fileContents = await file.text()
      if (!fileContents.trim()) {
        continue
      }

      const parsed = parseCsvContent(fileContents, file.name)
      combinedIocs.push(...parsed.iocs)
      campaignCandidates.push(...parsed.campaignCandidates)
      metadataEntries.push(...parsed.metadataEntries)
      continue
    }

    if (fileName.endsWith('.txt')) {
      const fileContents = await file.text()
      if (!fileContents.trim()) {
        continue
      }

      const parsed = parseTxtContent(fileContents, file.name)
      combinedIocs.push(...parsed.iocs)
      metadataEntries.push(...parsed.metadataEntries)
      continue
    }

    if (fileName.endsWith('.xlsx')) {
      const arrayBuffer = await file.arrayBuffer()
      const parsed = parseXlsxContent(arrayBuffer, file.name)
      combinedIocs.push(...parsed.iocs)
      campaignCandidates.push(...parsed.campaignCandidates)
      metadataEntries.push(...parsed.metadataEntries)
      continue
    }

    unsupportedFiles.push(file?.name || 'unknown file')
  }

  if (unsupportedFiles.length) {
    throw new Error(`Unsupported file type(s): ${unsupportedFiles.join(', ')}. Upload only .csv, .txt, or .xlsx files.`)
  }

  if (!combinedIocs.length) {
    throw new Error('No IOC values were extracted from uploaded files.')
  }

  const uniqueCampaignNames = [...new Set(campaignCandidates)]
  const detectedCampaignName = findMostCommonValue(campaignCandidates)
  const campaignWarning = uniqueCampaignNames.length > 1
    ? `Multiple campaign names were found in CSV event_info: ${uniqueCampaignNames.join(', ')}. Using most common value.`
    : null

  return {
    rawText: combinedIocs.join('\n'),
    iocMetadata: metadataEntries,
    summary: {
      filesUploaded: uploadedFiles.length,
      iocsExtracted: combinedIocs.length,
      detectedCampaignName,
      campaignNamesFound: uniqueCampaignNames,
      warning: campaignWarning,
    },
  }
}

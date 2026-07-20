import { downloadCsvContent } from './downloadFile.js'

export const DEFENDER_CSV_FILENAME = 'defender_iocs.csv'

const DEFENDER_CSV_HEADERS = [
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
  suspiciousactivity: 'SuspiciousActivity',
  'suspicious activity': 'SuspiciousActivity',
  suspicious: 'SuspiciousActivity',
  unwantedsoftware: 'UnwantedSoftware',
  'unwanted software': 'UnwantedSoftware',
}

const DIRECT_CATEGORY_LOOKUP = {
  collection: 'Collection',
  commandandcontrol: 'CommandAndControl',
  credentialaccess: 'CredentialAccess',
  defenseevasion: 'DefenseEvasion',
  discovery: 'Discovery',
  execution: 'Execution',
  exfiltration: 'Exfiltration',
  exploit: 'Exploit',
  initialaccess: 'InitialAccess',
  lateralmovement: 'LateralMovement',
  malware: 'Malware',
  persistence: 'Persistence',
  privilegeescalation: 'PrivilegeEscalation',
  ransomware: 'Ransomware',
  suspiciousactivity: 'SuspiciousActivity',
  unwantedsoftware: 'UnwantedSoftware',
}

const FORMULA_PREFIX_CHARACTERS = ['=', '+', '-', '@', '\t', '\r', '\n']

function normalizeLookupValue(value) {
  return String(value || '').trim().toLowerCase()
}

function sanitizeSpreadsheetCell(value) {
  const text = String(value || '')
  if (!text) {
    return ''
  }

  if (FORMULA_PREFIX_CHARACTERS.some((prefix) => text.startsWith(prefix))) {
    return `'${text}`
  }

  return text
}

function toCsvValue(value) {
  if (value === null || value === undefined) {
    return ''
  }

  if (typeof value === 'boolean') {
    return sanitizeSpreadsheetCell(value ? 'True' : 'False')
  }

  return sanitizeSpreadsheetCell(String(value))
}

function escapeCsvValue(value) {
  const serialized = String(value ?? '')
  if (!/[",\n\r]/.test(serialized)) {
    return serialized
  }

  return `"${serialized.replace(/"/g, '""')}"`
}

function serializeCsvRows(rows) {
  const lines = [DEFENDER_CSV_HEADERS.join(',')]

  for (const row of rows) {
    lines.push(row.map((value) => escapeCsvValue(value)).join(','))
  }

  return `${lines.join('\r\n')}\r\n`
}

function bestValue(values) {
  if (!values || !values.length) {
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

      if (left[0] < right[0]) {
        return -1
      }

      if (left[0] > right[0]) {
        return 1
      }

      return 0
    })[0][0]
}

function normalizeCategory(rawCategory) {
  if (rawCategory === null || rawCategory === undefined) {
    return 'Malware'
  }

  const normalized = String(rawCategory).trim()
  if (!normalized) {
    return 'Malware'
  }

  const lowered = normalized.toLowerCase()
  if (DIRECT_CATEGORY_LOOKUP[lowered]) {
    return DIRECT_CATEGORY_LOOKUP[lowered]
  }

  const compact = lowered.replace(/_/g, ' ').replace(/-/g, ' ')
  const aliasKey = compact.replace(/\s+/g, ' ').trim()

  if (CATEGORY_ALIASES[aliasKey]) {
    return CATEGORY_ALIASES[aliasKey]
  }

  const collapsed = aliasKey.replace(/\s+/g, '')
  if (CATEGORY_ALIASES[collapsed]) {
    return CATEGORY_ALIASES[collapsed]
  }

  return 'Malware'
}

function buildMetadataLookup(iocMetadata) {
  const lookup = new Map()
  const allCampaignNames = []

  for (const row of iocMetadata || []) {
    const value = String(row?.value || '').trim()
    if (!value) {
      continue
    }

    const key = normalizeLookupValue(value)
    if (!lookup.has(key)) {
      lookup.set(key, {
        campaignNames: [],
        categories: [],
      })
    }

    const bucket = lookup.get(key)
    const campaignName = String(row?.campaignName || '').trim()
    const category = String(row?.category || '').trim()

    if (campaignName) {
      bucket.campaignNames.push(campaignName)
      allCampaignNames.push(campaignName)
    }

    if (category) {
      bucket.categories.push(category)
    }
  }

  return {
    lookup,
    detectedCampaignName: bestValue(allCampaignNames),
  }
}

function getMetadataBucket(indicator, lookup) {
  const originalKey = normalizeLookupValue(indicator?.original_value)
  if (originalKey && lookup.has(originalKey)) {
    return lookup.get(originalKey)
  }

  const refangedKey = normalizeLookupValue(indicator?.refanged_value)
  if (refangedKey && lookup.has(refangedKey)) {
    return lookup.get(refangedKey)
  }

  return {
    campaignNames: [],
    categories: [],
  }
}

function buildRowTitle(campaignName) {
  if (campaignName && campaignName.trim()) {
    return `${campaignName.trim()} IOC`
  }

  return 'General Threat Indicators'
}

function buildRowDescription(campaignName) {
  if (campaignName && campaignName.trim()) {
    return `Indicators associated with ${campaignName.trim()}.`
  }

  return 'Threat indicators manually submitted for blocking and investigation.'
}

export function buildDefenderCsv({
  indicators = [],
  iocMetadata = [],
  campaignName = null,
  campaign_name = null,
  defaultCategory = null,
} = {}) {
  const { lookup, detectedCampaignName } = buildMetadataLookup(iocMetadata)
  const manualCampaignName = String(campaignName || '').trim() || String(campaign_name || '').trim() || null
  const rows = []

  for (const indicator of indicators || []) {
    if (!indicator?.valid || !indicator?.indicator_type) {
      continue
    }

    const indicatorType = String(indicator.indicator_type || '').trim().toLowerCase()
    if (indicatorType === 'senderemailaddress') {
      continue
    }

    const metadataBucket = getMetadataBucket(indicator, lookup)
    const rowCategory = bestValue(metadataBucket.categories)
    const campaignForRow = manualCampaignName || bestValue(metadataBucket.campaignNames) || detectedCampaignName
    const category = normalizeCategory(rowCategory || defaultCategory)

    rows.push([
      toCsvValue(indicator.indicator_type),
      toCsvValue(indicator.refanged_value),
      '',
      toCsvValue(indicator.action),
      toCsvValue(indicator.severity),
      toCsvValue(buildRowTitle(campaignForRow)),
      toCsvValue(buildRowDescription(campaignForRow)),
      '',
      '',
      toCsvValue(category),
      '',
      toCsvValue(indicator.generate_alert),
    ])
  }

  return `\ufeff${serializeCsvRows(rows)}`
}

export function downloadDefenderCsv(exportData = {}) {
  const csvContent = buildDefenderCsv(exportData)
  downloadCsvContent(csvContent, DEFENDER_CSV_FILENAME)

  return {
    filename: DEFENDER_CSV_FILENAME,
  }
}

export function compareDefenderCsvOutputs(expectedCsv, actualCsv) {
  const encoder = new TextEncoder()
  const expectedBytes = encoder.encode(String(expectedCsv ?? ''))
  const actualBytes = encoder.encode(String(actualCsv ?? ''))
  const minLength = Math.min(expectedBytes.length, actualBytes.length)

  for (let index = 0; index < minLength; index += 1) {
    if (expectedBytes[index] !== actualBytes[index]) {
      return {
        equal: false,
        firstDifferentByte: index,
        expectedByte: expectedBytes[index],
        actualByte: actualBytes[index],
        expectedLength: expectedBytes.length,
        actualLength: actualBytes.length,
      }
    }
  }

  if (expectedBytes.length !== actualBytes.length) {
    return {
      equal: false,
      firstDifferentByte: minLength,
      expectedByte: expectedBytes[minLength] ?? null,
      actualByte: actualBytes[minLength] ?? null,
      expectedLength: expectedBytes.length,
      actualLength: actualBytes.length,
    }
  }

  return {
    equal: true,
    firstDifferentByte: null,
    expectedByte: null,
    actualByte: null,
    expectedLength: expectedBytes.length,
    actualLength: actualBytes.length,
  }
}

import { downloadCsvContent } from './downloadFile.js'

const QRADAR_FILENAME_SUFFIX = 'qradar-ips.csv'
const QRADAR_FILENAME_FALLBACK = 'qradar-ips.csv'

function normalizeRawType(indicatorType) {
  return String(indicatorType || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_]/g, '')
}

function resolveQradarType(indicator) {
  const type = normalizeRawType(indicator?.indicator_type)

  if (type === 'ipv4') {
    return 'ipv4'
  }

  if (type === 'ipaddress' || type === 'ip') {
    const value = String(indicator?.refanged_value || indicator?.original_value || '')
    return value.includes(':') ? null : 'ipv4'
  }

  return null
}

function getIndicatorValue(indicator) {
  return String(indicator?.refanged_value || indicator?.original_value || '').trim()
}

function normalizeForDedupe(value) {
  return value.toLowerCase()
}

export function getQradarIpv4Values(indicators) {
  const seen = new Set()
  const values = []

  for (const indicator of indicators || []) {
    if (!indicator?.valid) {
      continue
    }

    if (resolveQradarType(indicator) !== 'ipv4') {
      continue
    }

    const value = getIndicatorValue(indicator)
    if (!value) {
      continue
    }

    const dedupeKey = normalizeForDedupe(value)
    if (seen.has(dedupeKey)) {
      continue
    }

    seen.add(dedupeKey)
    values.push(value)
  }

  return values
}

export function getQradarEligibleCount(indicators) {
  return getQradarIpv4Values(indicators).length
}

export function buildQradarCsv(indicators) {
  const values = getQradarIpv4Values(indicators)
  if (!values.length) {
    return null
  }

  return {
    values,
    csv: values.join('\n'),
  }
}

export function buildQradarExportFilename() {
  return QRADAR_FILENAME_FALLBACK
}

export function exportQradarCsv(indicators, { campaignName } = {}) {
  const exportData = buildQradarCsv(indicators)
  if (!exportData) {
    return null
  }

  const filename = buildQradarExportFilename(campaignName)
  downloadCsvContent(exportData.csv, filename)

  return {
    filename,
    count: exportData.values.length,
  }
}

const LINE_SEPARATOR = /\r?\n/

const REFANG_PATTERNS = [
  ['hxxps[://]', 'https://'],
  ['hxxp[://]', 'http://'],
  ['hxxps[:]//', 'https://'],
  ['hxxp[:]//', 'http://'],
  ['hxxps://', 'https://'],
  ['hxxp://', 'http://'],
  ['https[:]//', 'https://'],
  ['http[:]//', 'http://'],
  ['[.]', '.'],
  ['(.)', '.'],
  ['{.}', '.'],
  ['[dot]', '.'],
  ['(dot)', '.'],
  [' dot ', '.'],
  ['[:]', ':'],
  ['[@]', '@'],
  ['(at)', '@'],
  ['[at]', '@'],
]

function refang(value) {
  let normalized = String(value || '').trim().replace(/^['"]|['"]$/g, '')
  for (const [fromValue, toValue] of REFANG_PATTERNS) {
    normalized = normalized.split(fromValue).join(toValue)
  }

  normalized = normalized.replace(/\\\./g, '.')
  normalized = normalized.replace(/\s+/g, '')
  return normalized
}

function classifyType(refangedValue) {
  if (/^[0-9a-fA-F]{32}$/.test(refangedValue)) {
    return 'FileMd5'
  }

  if (/^[0-9a-fA-F]{40}$/.test(refangedValue)) {
    return 'FileSha1'
  }

  if (/^[0-9a-fA-F]{64}$/.test(refangedValue)) {
    return 'FileSha256'
  }

  if (/^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/.test(refangedValue)) {
    return 'IpAddress'
  }

  if (/^(?:[0-9A-Fa-f]{1,4}:){1,7}[0-9A-Fa-f]{1,4}$/.test(refangedValue)
    || /^(?:[0-9A-Fa-f]{1,4}:){1,7}:$/.test(refangedValue)
    || /^::1$/.test(refangedValue)) {
    return 'IpAddress'
  }

  if (/^https?:\/\/.+/.test(refangedValue)) {
    return 'Url'
  }

  if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(refangedValue)) {
    return 'SenderEmailAddress'
  }

  if (/^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/.test(refangedValue)) {
    return 'DomainName'
  }

  return null
}

export function getIndicatorKey(indicator) {
  if (!indicator) {
    return null
  }

  const type = String(indicator.indicator_type || '').trim() || 'None'
  const refangedValue = String(indicator.refanged_value || indicator.original_value || '').trim().toLowerCase()
  if (!refangedValue) {
    return null
  }

  return `${type}::${refangedValue}`
}

function getValueKey(value) {
  const cleanedValue = String(value || '').trim()
  if (!cleanedValue) {
    return null
  }

  const refangedValue = refang(cleanedValue)
  const indicatorType = classifyType(refangedValue)

  return `${indicatorType || 'None'}::${refangedValue.toLowerCase()}`
}

function getLinesFromIndicators(indicators) {
  const lines = []

  for (const indicator of indicators || []) {
    const value = String(indicator?.original_value || indicator?.refanged_value || '').trim()
    if (!value) {
      continue
    }

    lines.push(value)
  }

  return lines
}

function getLinesFromRawText(rawText) {
  return String(rawText || '')
    .split(LINE_SEPARATOR)
    .map((line) => line.trim())
    .filter(Boolean)
}

function dedupeLines(lines) {
  const seen = new Set()
  const deduped = []

  for (const line of lines || []) {
    const key = getValueKey(line)
    if (!key) {
      continue
    }

    if (seen.has(key)) {
      continue
    }

    seen.add(key)
    deduped.push(line)
  }

  return { lines: deduped, keys: seen }
}

function mergeMetadata(existingMetadata, incomingMetadata, acceptedNewKeys) {
  const merged = [...(existingMetadata || [])]
  const seenKeys = new Set()

  for (const row of existingMetadata || []) {
    const key = getValueKey(row?.value)
    if (key) {
      seenKeys.add(key)
    }
  }

  for (const row of incomingMetadata || []) {
    const key = getValueKey(row?.value)
    if (!key) {
      continue
    }

    if (!acceptedNewKeys.has(key)) {
      continue
    }

    if (seenKeys.has(key)) {
      continue
    }

    seenKeys.add(key)
    merged.push(row)
  }

  return merged
}

export function mergeAccumulatedSubmission({
  currentPayload,
  currentResult,
  incomingPayload,
  incomingResult,
}) {
  const currentLines = currentResult?.indicators?.length
    ? getLinesFromIndicators(currentResult.indicators)
    : getLinesFromRawText(currentPayload?.rawText)

  const incomingLines = incomingResult?.indicators?.length
    ? getLinesFromIndicators(incomingResult.indicators)
    : getLinesFromRawText(incomingPayload?.rawText)

  const existingDeduped = dedupeLines(currentLines)
  const mergedLineCandidates = [...existingDeduped.lines]
  const acceptedNewKeys = new Set()

  for (const line of incomingLines) {
    const key = getValueKey(line)
    if (!key) {
      continue
    }

    if (existingDeduped.keys.has(key)) {
      continue
    }

    existingDeduped.keys.add(key)
    acceptedNewKeys.add(key)
    mergedLineCandidates.push(line)
  }

  const mergedMetadata = mergeMetadata(
    currentPayload?.iocMetadata || [],
    incomingPayload?.iocMetadata || [],
    acceptedNewKeys,
  )

  return {
    rawText: mergedLineCandidates.join('\n'),
    lookbackDays: incomingPayload?.lookbackDays,
    campaignName: incomingPayload?.campaignName || null,
    defaultCategory: incomingPayload?.defaultCategory || null,
    iocMetadata: mergedMetadata.length ? mergedMetadata : null,
  }
}

const TYPE_ORDER = [
  'ipv4',
  'ipv6',
  'md5',
  'sha1',
  'sha256',
  'domain',
  'url',
  'sender_email',
]

const QUOTED_TYPES = new Set(['url', 'sender_email'])

const TYPE_ALIASES = {
  ipv4: 'ipv4',
  ipv6: 'ipv6',
  ipaddress: 'ipaddress',
  ip: 'ipaddress',
  filemd5: 'md5',
  md5: 'md5',
  filesha1: 'sha1',
  sha1: 'sha1',
  filesha256: 'sha256',
  sha256: 'sha256',
  domainname: 'domain',
  domain: 'domain',
  domains: 'domain',
  url: 'url',
  urls: 'url',
  senderemailaddress: 'sender_email',
  sender_email_address: 'sender_email',
  senderemail: 'sender_email',
  email: 'sender_email',
}

function normalizeRawType(indicatorType) {
  return String(indicatorType || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_]/g, '')
}

function resolveIndicatorType(indicator) {
  const normalizedType = normalizeRawType(indicator?.indicator_type)
  const mapped = TYPE_ALIASES[normalizedType]

  if (!mapped) {
    return null
  }

  if (mapped !== 'ipaddress') {
    return mapped
  }

  const value = String(indicator?.refanged_value || indicator?.original_value || '')
  return value.includes(':') ? 'ipv6' : 'ipv4'
}

function escapeForQuotedValue(value) {
  return value.replace(/"/g, '\\"')
}

function formatQueryValue(typeKey, value) {
  if (!QUOTED_TYPES.has(typeKey)) {
    return value
  }

  return `"${escapeForQuotedValue(value)}"`
}

function getIndicatorValue(indicator) {
  return String(indicator?.refanged_value || indicator?.original_value || '').trim()
}

export const CROWDSTRIKE_ADVANCED_EVENT_SEARCH_TYPE_ORDER = [...TYPE_ORDER]

export function buildCrowdStrikeAdvancedEventSearchQuery(indicators) {
  const valuesByType = new Map(TYPE_ORDER.map((typeKey) => [typeKey, []]))
  const seen = new Set()

  for (const indicator of indicators || []) {
    if (!indicator?.valid) {
      continue
    }

    const typeKey = resolveIndicatorType(indicator)
    if (!typeKey || !valuesByType.has(typeKey)) {
      continue
    }

    const value = getIndicatorValue(indicator)
    if (!value) {
      continue
    }

    const dedupeKey = `${typeKey}::${value.toLowerCase()}`
    if (seen.has(dedupeKey)) {
      continue
    }

    seen.add(dedupeKey)
    valuesByType.get(typeKey).push(value)
  }

  const orderedValues = []
  let uniqueTypeCount = 0

  for (const typeKey of TYPE_ORDER) {
    const values = valuesByType.get(typeKey)
    if (!values.length) {
      continue
    }

    uniqueTypeCount += 1
    for (const value of values) {
      orderedValues.push(formatQueryValue(typeKey, value))
    }
  }

  if (!orderedValues.length) {
    return null
  }

  return {
    query: orderedValues.join(' or '),
    totalUniqueIocCount: orderedValues.length,
    uniqueTypeCount,
  }
}
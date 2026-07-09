export const DETECTED_EMPTY_MESSAGE = 'No supported IOCs were detected.'

export function getFriendlyIgnoredReason(reason) {
  if (reason === 'unsupported_indicator' || reason === 'empty_value') {
    return 'Ignored non-IOC text'
  }

  if (!reason) {
    return 'Ignored'
  }

  return 'Ignored'
}

function hasKnownType(ioc) {
  const type = String(ioc?.indicator_type || '').trim()
  if (!type) {
    return false
  }

  const lowered = type.toLowerCase()
  return lowered !== 'n/a' && lowered !== 'unknown'
}

export function splitDetectedAndIgnored(indicators) {
  const detected = []
  const ignored = []

  for (const ioc of indicators || []) {
    const isDetected = Boolean(ioc?.valid) && hasKnownType(ioc)

    if (isDetected) {
      detected.push(ioc)
      continue
    }

    ignored.push({
      original_value: ioc?.original_value || '',
      refanged_value: ioc?.refanged_value || '',
      reason: getFriendlyIgnoredReason(ioc?.reason),
    })
  }

  return { detected, ignored }
}

export function isIgnoredCollapsedByDefault() {
  return true
}

export function toggleIgnoredExpanded(currentValue) {
  return !Boolean(currentValue)
}

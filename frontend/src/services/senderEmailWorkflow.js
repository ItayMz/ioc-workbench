function isSenderEmailIndicator(indicator) {
  return Boolean(indicator?.valid)
    && String(indicator?.indicator_type || '').trim().toLowerCase() === 'senderemailaddress'
}

export function getDetectedSenderEmailAddresses(indicators) {
  const seen = new Set()
  const values = []

  for (const indicator of indicators || []) {
    if (!isSenderEmailIndicator(indicator)) {
      continue
    }

    const value = String(indicator?.refanged_value || indicator?.original_value || '').trim().toLowerCase()
    if (!value) {
      continue
    }

    if (seen.has(value)) {
      continue
    }

    seen.add(value)
    values.push(value)
  }

  return values
}

export function buildSenderEmailCopyPayload(senderEmailAddresses) {
  return (senderEmailAddresses || []).join('\n')
}

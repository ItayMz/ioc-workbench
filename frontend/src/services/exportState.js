const NO_VALID_IOCS_EXPORT_MESSAGE = 'No valid IOCs are available to export. Paste IOC text or upload one or more CSV/TXT files first.'

function getValidIocCount(lastSuccessfulParseResult) {
  if (!lastSuccessfulParseResult) {
    return 0
  }

  if (typeof lastSuccessfulParseResult.valid_count === 'number') {
    return lastSuccessfulParseResult.valid_count
  }

  if (typeof lastSuccessfulParseResult.summary?.valid === 'number') {
    return lastSuccessfulParseResult.summary.valid
  }

  if (typeof lastSuccessfulParseResult.summary?.valid_count === 'number') {
    return lastSuccessfulParseResult.summary.valid_count
  }

  return 0
}

export function resolveExportRequest({ lastSuccessfulParsePayload, lastSuccessfulParseResult }) {
  const hasPayloadText = Boolean(lastSuccessfulParsePayload?.rawText?.trim())
  const validIocCount = getValidIocCount(lastSuccessfulParseResult)
  const canExport = hasPayloadText && validIocCount > 0

  if (!canExport) {
    return {
      canExport: false,
      payload: null,
      error: NO_VALID_IOCS_EXPORT_MESSAGE,
    }
  }

  return {
    canExport: true,
    payload: lastSuccessfulParsePayload,
    error: null,
  }
}

export function getInitialRawText() {
  return ''
}

export { NO_VALID_IOCS_EXPORT_MESSAGE }

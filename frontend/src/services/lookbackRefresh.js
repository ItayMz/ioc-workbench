export const DEFAULT_LOOKBACK_DAYS = 90
export const LOOKBACK_REFRESH_FAILURE_MESSAGE = 'Unable to refresh KQL queries for the selected lookback. Showing previous results.'

export function shouldAttemptLookbackRefresh({
  nextLookbackDays,
  backendConnected,
  canExport,
  lastSuccessfulParsePayload,
  refreshInFlight,
}) {
  if (!backendConnected || !canExport || refreshInFlight) {
    return false
  }

  if (!lastSuccessfulParsePayload) {
    return false
  }

  return Number(nextLookbackDays) !== Number(lastSuccessfulParsePayload.lookbackDays)
}

export function buildLookbackRefreshPayload(lastSuccessfulParsePayload, nextLookbackDays) {
  if (!lastSuccessfulParsePayload) {
    return null
  }

  return {
    ...lastSuccessfulParsePayload,
    lookbackDays: Number(nextLookbackDays),
  }
}

export function applyLookbackRefreshResult(currentParseResult, refreshedResult) {
  const nextKqlQueries = refreshedResult?.kqlQueries || currentParseResult?.kqlQueries || {}

  if (!currentParseResult) {
    return {
      ...refreshedResult,
      kqlQueries: nextKqlQueries,
    }
  }

  return {
    ...currentParseResult,
    kqlQueries: nextKqlQueries,
  }
}

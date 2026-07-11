export const BACKEND_CONNECTION_STATES = {
  CHECKING: 'checking',
  WAKING: 'waking',
  CONNECTED: 'connected',
  UNAVAILABLE: 'unavailable',
}

export const HEALTH_RETRY_INTERVAL_MS = 2000
export const HEALTH_MAX_DURATION_MS = 60000

const NETWORK_ERROR_PATTERN = /failed to fetch|networkerror|load failed|network request failed/i

function defaultSleep(delayMs) {
  return new Promise((resolve) => {
    setTimeout(resolve, delayMs)
  })
}

export function getBackendStatusContent(state) {
  if (state === BACKEND_CONNECTION_STATES.CHECKING) {
    return {
      label: 'Backend status',
      title: 'Connecting to backend...',
      description: '',
      tone: 'checking',
    }
  }

  if (state === BACKEND_CONNECTION_STATES.WAKING) {
    return {
      label: 'Backend status',
      title: 'Waking backend service...',
      description: 'The service may take a few seconds to start after inactivity.',
      tone: 'waking',
    }
  }

  if (state === BACKEND_CONNECTION_STATES.CONNECTED) {
    return {
      label: 'Backend status',
      title: 'Backend connected.',
      description: '',
      tone: 'connected',
    }
  }

  return {
    label: 'Backend status',
    title: 'Backend is currently unavailable. Please try again shortly.',
    description: '',
    tone: 'unavailable',
  }
}

export function isBackendConnected(state) {
  return state === BACKEND_CONNECTION_STATES.CONNECTED
}

export function shouldDisableBackendActions(connectionState, loading) {
  return Boolean(loading) || !isBackendConnected(connectionState)
}

export function isLikelyNetworkError(error) {
  if (!error) {
    return false
  }

  if (error instanceof TypeError) {
    return true
  }

  const message = String(error?.message || '')
  return NETWORK_ERROR_PATTERN.test(message)
}

export async function waitForBackendAvailability({
  checkBackendHealth,
  onStateChange,
  intervalMs = HEALTH_RETRY_INTERVAL_MS,
  maxDurationMs = HEALTH_MAX_DURATION_MS,
  sleep = defaultSleep,
  now = () => Date.now(),
}) {
  const startedAt = now()
  let attempt = 0

  while (now() - startedAt <= maxDurationMs) {
    onStateChange?.(
      attempt === 0
        ? BACKEND_CONNECTION_STATES.CHECKING
        : BACKEND_CONNECTION_STATES.WAKING,
    )

    const isHealthy = await checkBackendHealth()
    if (isHealthy) {
      onStateChange?.(BACKEND_CONNECTION_STATES.CONNECTED)
      return true
    }

    attempt += 1

    if (now() - startedAt + intervalMs > maxDurationMs) {
      break
    }

    await sleep(intervalMs)
  }

  onStateChange?.(BACKEND_CONNECTION_STATES.UNAVAILABLE)
  return false
}

export async function runRequestWithSingleHealthRecovery(request, options) {
  const {
    checkBackendHealth,
    onStateChange,
    intervalMs,
    maxDurationMs,
    sleep,
    now,
  } = options

  try {
    return await request()
  } catch (error) {
    if (!isLikelyNetworkError(error)) {
      throw error
    }

    const healthy = await waitForBackendAvailability({
      checkBackendHealth,
      onStateChange,
      intervalMs,
      maxDurationMs,
      sleep,
      now,
    })

    if (!healthy) {
      throw error
    }

    return request()
  }
}

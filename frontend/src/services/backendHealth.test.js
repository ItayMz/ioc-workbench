import assert from 'node:assert/strict'
import test from 'node:test'

import {
  BACKEND_CONNECTION_STATES,
  isLikelyNetworkError,
  runRequestWithSingleHealthRecovery,
  shouldDisableBackendActions,
  waitForBackendAvailability,
} from './backendHealth.js'

test('app startup health flow begins in checking and retries to waking before unavailable', async () => {
  const seenStates = []
  let currentTime = 0
  let attempts = 0

  const healthy = await waitForBackendAvailability({
    checkBackendHealth: async () => {
      attempts += 1
      return false
    },
    onStateChange: (state) => {
      seenStates.push(state)
    },
    intervalMs: 2000,
    maxDurationMs: 6000,
    now: () => currentTime,
    sleep: async (delayMs) => {
      currentTime += delayMs
    },
  })

  assert.equal(healthy, false)
  assert.equal(attempts, 4)
  assert.equal(seenStates[0], BACKEND_CONNECTION_STATES.CHECKING)
  assert.equal(seenStates.includes(BACKEND_CONNECTION_STATES.WAKING), true)
  assert.equal(seenStates.at(-1), BACKEND_CONNECTION_STATES.UNAVAILABLE)
})

test('controls are disabled while backend is unavailable and enabled after connected', () => {
  assert.equal(shouldDisableBackendActions(BACKEND_CONNECTION_STATES.CHECKING, false), true)
  assert.equal(shouldDisableBackendActions(BACKEND_CONNECTION_STATES.WAKING, false), true)
  assert.equal(shouldDisableBackendActions(BACKEND_CONNECTION_STATES.UNAVAILABLE, false), true)
  assert.equal(shouldDisableBackendActions(BACKEND_CONNECTION_STATES.CONNECTED, false), false)
  assert.equal(shouldDisableBackendActions(BACKEND_CONNECTION_STATES.CONNECTED, true), true)
})

test('failed request retries once after backend health recovery', async () => {
  let requestAttempts = 0
  let currentTime = 0
  const stateChanges = []

  const result = await runRequestWithSingleHealthRecovery(
    async () => {
      requestAttempts += 1
      if (requestAttempts === 1) {
        throw new TypeError('Failed to fetch')
      }

      return { ok: true }
    },
    {
      checkBackendHealth: async () => true,
      onStateChange: (state) => {
        stateChanges.push(state)
      },
      now: () => currentTime,
      sleep: async (delayMs) => {
        currentTime += delayMs
      },
    },
  )

  assert.deepEqual(result, { ok: true })
  assert.equal(requestAttempts, 2)
  assert.equal(stateChanges[0], BACKEND_CONNECTION_STATES.CHECKING)
  assert.equal(stateChanges.at(-1), BACKEND_CONNECTION_STATES.CONNECTED)
})

test('request recovery does not enter infinite retry loop when retry also fails', async () => {
  let requestAttempts = 0

  await assert.rejects(async () => {
    await runRequestWithSingleHealthRecovery(
      async () => {
        requestAttempts += 1
        throw new TypeError('Failed to fetch')
      },
      {
        checkBackendHealth: async () => true,
      },
    )
  })

  assert.equal(requestAttempts, 2)
})

test('network error detection catches fetch failures and ignores API errors', () => {
  assert.equal(isLikelyNetworkError(new TypeError('Failed to fetch')), true)
  assert.equal(isLikelyNetworkError(new Error('Request failed. Check backend logs for details.')), false)
})
